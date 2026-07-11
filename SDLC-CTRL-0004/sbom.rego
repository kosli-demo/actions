package policy

import rego.v1

# Dependency Management / SBOM (SDLC-CTRL-0004)
# https://sdlc.kosli.com/controls/build/dependency_management/
# Rego policy reference: https://docs.kosli.com/policy-reference/rego_policy#rego-policy
#
# Control intent (SDLC-CTRL-0004): "Every dependency is defined securely,
# managed, and auditable as part of the software development lifecycle."
# This policy checks the artifact's SBOM against that intent:
#   defined    -> the SBOM exists, is non-empty, and is a real dependency graph
#   managed    -> every package has a concrete version
#   auditable  -> every package has a resolvable purl identity
#
# Package licenses are recorded in the SBOM facts for visibility but are NOT
# checked: a container image always ships GPL-licensed base-OS packages, and
# syft cannot resolve licenses for many ecosystems (Go modules in particular),
# so gating on license would fail every build without adding real assurance.
#
# Per-package checks are strict (every package must satisfy them) except where a
# package is explicitly waived by the per-service overrides allow-list (see PARAMS).
#
# WHAT THIS POLICY READS
# ----------------------
# kosli evaluate trail exposes only the trail JSON as input.trail. It does NOT
# expose raw attestation attachments (the raw sbom.spdx.json blob is invisible
# to rego). It DOES expose structured data attested via
#   kosli attest custom --type <schema> --attestation-data <file> --name <name> --fingerprint <digest>
# under input.trail...attestations_statuses[<name>].attestation_data.
#
# So the workflow must distill sbom.spdx.json (SPDX 2.3 JSON) into the small,
# rego-friendly attestation_data contract below, and attest it BEFORE this
# policy is evaluated. This policy holds the checks; the jq step only reshapes.
#
# REQUIRED attestation_data CONTRACT (produced by the sbom-facts.jq distill step)
# -------------------------------------------------------------------------------
# {
#   "spec_version": "SPDX-2.3",              # SPDX .spdxVersion
#   "created":      "2026-07-08T12:00:00Z",  # SPDX .creationInfo.created
#   "creators":     ["Tool: syft-..."],      # SPDX .creationInfo.creators
#   "relationship_count": 143,               # (.relationships | length)
#   "packages": [                            # one entry per SPDX .packages[]
#     {
#       "name":    "openssl",                # .name
#       "version": "3.0.13",                 # .versionInfo
#       "license": "Apache-2.0",             # recorded for visibility, not checked
#       "purl":    "pkg:deb/debian/openssl@3.0.13"  # externalRefs[] purl, else ""
#     }
#   ]
# }
#
# VERIFY THE INPUT PATH before trusting this policy. Per the Kosli docs, dump the
# real trail shape and confirm the artifacts_statuses / attestations_statuses path:
#   kosli evaluate trail "$KOSLI_TRAIL" --policy allow-all.rego \
#     --show-input --output json | jq '.input.trail.compliance_status'
# If the SBOM facts attestation lands elsewhere, adjust the single `sbom` line below.
#
# PARAMS (kosli evaluate trail --params '{...}')
#   artifact_name          template reference name of the artifact (eg "saver")
#   sbom_attestation_name  --name of the custom SBOM-facts attestation (eg "sbom-facts")
#   min_packages           minimum package count for a non-empty inventory (eg 1)
#   allowed_spec_versions  allowed SPDX spec versions (eg ["SPDX-2.3"])
#   now                    evaluation date "YYYY-MM-DD"; overrides expire against it
#   overrides             per-service allow-list (see sbom-overrides.schema.json).
#                          Each entry waives one check for one package:
#                            {package, check: version|purl, reason, expires}
#                          A missing / expired / malformed entry waives nothing.
#
# Every param is aliased at the top. A missing param becomes undefined, so the
# rule that uses it fails and allow stays false -- fail toward non-compliance.
# The overrides list is additive (it only makes packages pass), so a missing or
# invalid overrides list makes fewer packages pass -- also fail toward non-compliance.

default allow := false

# Artifact template reference name; falls back to "artifact" to match SDLC-CTRL-0002.
artifact_name := name if {
	name := data.params.artifact_name
	is_string(name)
} else := "artifact"

# Name of the custom attestation carrying the distilled SBOM facts. No fallback:
# if absent, sbom below is undefined and the policy is non-compliant.
sbom_attestation_name := data.params.sbom_attestation_name

min_packages := data.params.min_packages

# Evaluation date ("YYYY-MM-DD") used to expire overrides. If absent, no
# override is active -- exemptions fail toward non-compliance.
now_date := data.params.now

# If absent the comprehension yields the empty set, blocking every document.
allowed_spec_versions := {v | some v in data.params.allowed_spec_versions}

# ---------------------------------------------------------------------------
# Single source of truth for where the SBOM facts live in the trail input.
# Adjust ONLY this line if --show-input reveals a different path.
# ---------------------------------------------------------------------------
sbom := input.trail.compliance_status.artifacts_statuses[artifact_name].attestations_statuses[sbom_attestation_name].attestation_data

packages := sbom.packages

# ---------------------------------------------------------------------------
# allow is driven by positive assertions (every condition must hold), never by
# the absence of violations. A silently-undefined reference can then only fail a
# condition (blocking compliance); it can never fabricate a compliant result.
# ---------------------------------------------------------------------------
allow if {
	inventory_present
	inventory_non_empty
	document_well_formed
	has_dependency_graph
	all_packages_versioned
	all_packages_identified
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A field is unset if it is absent, empty, or an SPDX no-value sentinel.
is_unset(v) if not is_string(v)

is_unset(v) if v == ""

is_unset(v) if upper(v) == "NOASSERTION"

is_unset(v) if upper(v) == "NONE"

# The per-package field a named check inspects.
field_of(pkg, "version") := pkg.version

field_of(pkg, "purl") := pkg.purl

# A package satisfies a check when the field is set, or when the package is
# explicitly exempted from that check by the overrides allow-list.
package_satisfies(pkg, check) if not is_unset(field_of(pkg, check))

package_satisfies(pkg, check) if exempt(pkg, check)

# An overrides entry waives one check for one package only when it has a
# non-empty reason and is not expired. A missing / malformed / expired entry
# waives nothing.
exempt(pkg, check) if {
	some e in data.params.overrides
	e.package == pkg.name
	e.check == check
	is_string(e.reason)
	e.reason != ""
	override_active(e)
}

# Active while the evaluation date is on or before the entry's expiry date.
# Both are "YYYY-MM-DD", so a lexicographic compare is a chronological compare.
override_active(e) if {
	is_string(e.expires)
	is_string(now_date)
	e.expires >= now_date
}

# ---------------------------------------------------------------------------
# Positive conditions
# ---------------------------------------------------------------------------

# defined: a SBOM facts attestation is present on the trail for this artifact.
sbom_present if is_object(sbom)

# defined: the SBOM facts attestation is present and carries a package array.
inventory_present if {
	sbom_present
	is_array(packages)
}

# defined: the inventory is not suspiciously empty (empty usually means the
# SBOM generation silently failed).
inventory_non_empty if count(packages) >= min_packages

# auditable: the document declares a known spec version, a creation timestamp,
# and at least one generating tool.
document_well_formed if {
	sbom.spec_version in allowed_spec_versions
	is_string(sbom.created)
	sbom.created != ""
	count(sbom.creators) > 0
}

# defined: the SBOM is a real dependency graph rooted at the image, not a flat
# list with no relationships.
has_dependency_graph if sbom.relationship_count > 0

# managed: every package pins a concrete version (or is exempted).
all_packages_versioned if {
	every pkg in packages {
		package_satisfies(pkg, "version")
	}
}

# auditable: every package carries a resolvable purl identity (or is exempted).
all_packages_identified if {
	every pkg in packages {
		package_satisfies(pkg, "purl")
	}
}

# ---------------------------------------------------------------------------
# Violations (diagnostics only; they do not drive allow)
# ---------------------------------------------------------------------------

violations contains sprintf("no '%v' SBOM facts attestation found under artifact '%v' -- SBOM was not attested as structured data", [sbom_attestation_name, artifact_name]) if {
	not sbom_present
}

violations contains sprintf("'%v' SBOM facts attestation under artifact '%v' has no packages array", [sbom_attestation_name, artifact_name]) if {
	sbom_present
	not is_array(object.get(sbom, "packages", null))
}

violations contains sprintf("SBOM inventory has %d packages, below the minimum of %d", [count(packages), min_packages]) if {
	is_array(packages)
	not inventory_non_empty
}

violations contains sprintf("SBOM document metadata incomplete: spec_version '%v' not in allowed set, or created/creators missing", [object.get(sbom, "spec_version", "<missing>")]) if {
	sbom_present
	not document_well_formed
}

violations contains "SBOM has no relationships -- it is not a dependency graph rooted at the image" if {
	sbom_present
	not has_dependency_graph
}

violations contains sprintf("package '%v' has no concrete version", [pkg.name]) if {
	some pkg in packages
	is_unset(pkg.version)
	not exempt(pkg, "version")
}

violations contains sprintf("package '%v' has no resolvable purl identity", [pkg.name]) if {
	some pkg in packages
	is_unset(pkg.purl)
	not exempt(pkg, "purl")
}

# An expired override no longer waives its package, so the check above fires
# again; this names the stale override so it can be renewed or removed.
violations contains sprintf("override for package '%v' check '%v' expired on %v -- renew or remove it", [e.package, e.check, e.expires]) if {
	some e in data.params.overrides
	is_string(e.expires)
	is_string(now_date)
	e.expires < now_date
	some pkg in packages
	pkg.name == e.package
	is_unset(field_of(pkg, e.check))
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

output := {
	"allow": allow,
	"violations": violations,
}
