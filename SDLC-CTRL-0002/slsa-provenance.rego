package policy

import rego.v1

# Binary Provenance (SDLC-CTRL-0002) -- SLSA-predicate variant
# https://sdlc.kosli.com/controls/build/binary_provenance/
# Rego policy reference: https://docs.kosli.com/policy-reference/rego_policy#rego-policy
#
# Control intent (SDLC-CTRL-0002): "Every software artifact running in a
# production system has known provenance, established through cryptographic
# content-addressable identities."
#
# This policy evaluates the SLSA v1 provenance the builder itself attested
# (from the GitHub sigstore bundle), distilled into a provenance-facts custom
# attestation by provenance-facts.jq. It verifies, against the builder's own
# signed statement:
#   known identity  -> the provenance subject digest IS this artifact's fingerprint
#   known source    -> the builder-attested source commit IS the trail's commit,
#                       from an expected cyber-dojo repository
#   known builder   -> built by a trusted cyber-dojo reusable workflow, with the
#                       expected SLSA build type and predicate type
#
# WHAT THIS POLICY READS
# ----------------------
# kosli evaluate trail exposes only the trail JSON as input.trail. The workflow
# distils the GitHub sigstore bundle into the attestation_data contract below and
# attests it with
#   kosli attest custom --type provenance-facts --name <name> --fingerprint <digest>
# BEFORE this policy runs. This policy holds the checks; the jq only reshapes.
#
# REQUIRED attestation_data CONTRACT (produced by provenance-facts.jq)
# -------------------------------------------------------------------
# {
#   "predicate_type":    "https://slsa.dev/provenance/v1",
#   "build_type":        "https://actions.github.io/buildtypes/workflow/v1",
#   "builder_id":        "https://github.com/cyber-dojo/reusable-actions-workflows/.github/workflows/secure-...-build.yml@refs/heads/main",
#   "subject_digest":    "<sha256 of the image the provenance is about>",
#   "source_repo":       "https://github.com/cyber-dojo/<repo>",
#   "source_ref":        "refs/heads/main",
#   "source_uri":        "git+https://github.com/cyber-dojo/<repo>@refs/heads/main",
#   "source_git_commit": "<git commit the builder attests it built from>",
#   "invocation_id":     "https://github.com/cyber-dojo/<repo>/actions/runs/<id>/attempts/<n>"
# }
#
# VERIFY THE INPUT PATH with `kosli evaluate trail ... --show-input` before
# trusting this policy; adjust the single `prov` line if it lands elsewhere.
#
# PARAMS (kosli evaluate trail --params '{...}')
#   artifact_name             template reference name of the artifact (eg "nginx")
#   provenance_attestation_name  --name of the provenance-facts attestation (eg "provenance-facts")
#   allowed_predicate_types   allowed SLSA predicate types (eg ["https://slsa.dev/provenance/v1"])
#   allowed_build_types       allowed SLSA build types (eg ["https://actions.github.io/buildtypes/workflow/v1"])
#   expected_builder_id_prefix  builder.id must start with this (the trusted reusable workflow prefix)
#   expected_source_repo_prefix source_repo must start with this (eg "https://github.com/cyber-dojo/")
#
# Every param is aliased at the top. A missing param becomes undefined, so the
# rule that uses it fails and allow stays false -- fail toward non-compliance.

default allow := false

# Artifact template reference name; falls back to "artifact" to match the other controls.
artifact_name := name if {
	name := data.params.artifact_name
	is_string(name)
} else := "artifact"

# Name of the custom attestation carrying the distilled provenance facts. No
# fallback: if absent, prov below is undefined and the policy is non-compliant.
provenance_attestation_name := data.params.provenance_attestation_name

expected_builder_id_prefix := data.params.expected_builder_id_prefix

expected_source_repo_prefix := data.params.expected_source_repo_prefix

# If a param list is absent the comprehension yields the empty set, which
# matches nothing -- so the corresponding check fails and allow stays false.
allowed_predicate_types := {v | some v in data.params.allowed_predicate_types}

allowed_build_types := {v | some v in data.params.allowed_build_types}

# ---------------------------------------------------------------------------
# Single source of truth for where the provenance facts and the values they are
# cross-checked against live in the trail input. Adjust ONLY these lines if
# --show-input reveals a different path.
# ---------------------------------------------------------------------------
prov := input.trail.compliance_status.artifacts_statuses[artifact_name].attestations_statuses[provenance_attestation_name].attestation_data

artifact_fingerprint := input.trail.compliance_status.artifacts_statuses[artifact_name].artifact_fingerprint

trail_commit := input.trail.git_commit_info.sha1

# ---------------------------------------------------------------------------
# allow is driven by positive assertions (every condition must hold), never by
# the absence of violations. A silently-undefined reference can then only fail a
# condition (blocking compliance); it can never fabricate a compliant result.
# ---------------------------------------------------------------------------
allow if {
	provenance_present
	predicate_type_allowed
	build_type_allowed
	builder_trusted
	source_repo_trusted
	subject_matches_artifact
	source_commit_matches_trail
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Two content-addressable identities are equal only when both are present and
# equal (case-insensitive). The non-empty guard is essential: the distill emits
# "" for missing fields, and "" == "" must NOT count as a match.
digests_equal(a, b) if {
	is_string(a)
	a != ""
	is_string(b)
	lower(a) == lower(b)
}

has_prefix(s, prefix) if {
	is_string(s)
	is_string(prefix)
	startswith(s, prefix)
}

# ---------------------------------------------------------------------------
# Positive conditions
# ---------------------------------------------------------------------------

# known: a provenance-facts attestation is present on the trail for this artifact.
provenance_present if is_object(prov)

# known builder: the SLSA predicate type is an allowed one.
predicate_type_allowed if prov.predicate_type in allowed_predicate_types

# known builder: the SLSA build type is an allowed one.
build_type_allowed if prov.build_type in allowed_build_types

# known builder: built by a trusted cyber-dojo reusable workflow.
builder_trusted if has_prefix(prov.builder_id, expected_builder_id_prefix)

# known source: the attested source repository is an expected cyber-dojo repo.
source_repo_trusted if has_prefix(prov.source_repo, expected_source_repo_prefix)

# known identity: the provenance subject digest is this artifact's fingerprint.
subject_matches_artifact if digests_equal(prov.subject_digest, artifact_fingerprint)

# known source: the builder-attested source commit is the trail's commit.
source_commit_matches_trail if digests_equal(prov.source_git_commit, trail_commit)

# ---------------------------------------------------------------------------
# Violations (diagnostics only; they do not drive allow)
# ---------------------------------------------------------------------------

violations contains sprintf("no '%v' provenance-facts attestation found under artifact '%v' -- SLSA provenance was not attested as structured data", [provenance_attestation_name, artifact_name]) if {
	not provenance_present
}

violations contains sprintf("provenance predicate_type '%v' is not in the allowed set", [object.get(prov, "predicate_type", "<missing>")]) if {
	provenance_present
	not predicate_type_allowed
}

violations contains sprintf("provenance build_type '%v' is not in the allowed set", [object.get(prov, "build_type", "<missing>")]) if {
	provenance_present
	not build_type_allowed
}

violations contains sprintf("provenance builder '%v' is not a trusted builder (expected prefix '%v')", [object.get(prov, "builder_id", "<missing>"), expected_builder_id_prefix]) if {
	provenance_present
	not builder_trusted
}

violations contains sprintf("provenance source_repo '%v' is not an expected repository (expected prefix '%v')", [object.get(prov, "source_repo", "<missing>"), expected_source_repo_prefix]) if {
	provenance_present
	not source_repo_trusted
}

violations contains sprintf("provenance subject digest '%v' does not match the artifact fingerprint '%v'", [object.get(prov, "subject_digest", "<missing>"), object.get(input.trail.compliance_status.artifacts_statuses[artifact_name], "artifact_fingerprint", "<missing>")]) if {
	provenance_present
	not subject_matches_artifact
}

violations contains sprintf("provenance source commit '%v' does not match the trail commit '%v'", [object.get(prov, "source_git_commit", "<missing>"), object.get(input.trail.git_commit_info, "sha1", "<missing>")]) if {
	provenance_present
	not source_commit_matches_trail
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

output := {
	"allow": allow,
	"violations": violations,
}
