package policy

import rego.v1

# Artifact Binary Provenance (SDLC-CTRL-0002)
# https://sdlc.kosli.com/controls/build/binary_provenance/
#
# Input: {"trail": <trail JSON>} — kosli evaluate wraps the trail under input.trail
#
# Verifies the trail JSON contains all required provenance evidence:
#   ✓ SHA256 fingerprint                  [trail.artifacts_statuses.<name>.artifact_fingerprint]
#   ✓ Human-readable artifact name        [trail.events: artifact_creation_reported event]
#   ✓ Git commit that produced it         [trail.git_commit_info.sha1]
#   ✓ Repository reference                [trail.git_commit_info.url — the commit URL]
#   ✓ Build log URL                       [trail.origin_url]
#   ✗ Git repository state (clean/dirty)  — not captured in Kosli data model
#
default allow := false

# Artifact template reference name — matches the name given in the flow template.
artifact_name := name if {
    name := data.params.artifact_name
    is_string(name)
} else := "artifact"

allow if {
    artifact_fingerprint_recorded
    artifact_human_name_recorded
    git_commit_recorded
    repo_url_recorded
    build_url_recorded
}

# ---------------------------------------------------------------------------
# Positive conditions
# ---------------------------------------------------------------------------

artifact_fingerprint_recorded if {
    artifact := input.trail.compliance_status.artifacts_statuses[artifact_name]
    is_string(artifact.artifact_fingerprint)
    artifact.artifact_fingerprint != ""
}

artifact_human_name_recorded if {
    some event in input.trail.events
    event.type == "artifact_creation_reported"
    event.template_reference_name == artifact_name
    is_string(event.artifact_name)
    event.artifact_name != ""
}

git_commit_recorded if {
    is_string(input.trail.git_commit_info.sha1)
    input.trail.git_commit_info.sha1 != ""
}

repo_url_recorded if {
    is_string(input.trail.git_commit_info.url)
    input.trail.git_commit_info.url != ""
}

build_url_recorded if {
    is_string(input.trail.origin_url)
    input.trail.origin_url != ""
}

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

violations contains sprintf("no '%v' artifact found in trail — artifact was not attested", [artifact_name]) if {
    not input.trail.compliance_status.artifacts_statuses[artifact_name]
}

violations contains "artifact_fingerprint is missing or empty — SHA256 digest must be recorded" if {
    input.trail.compliance_status.artifacts_statuses[artifact_name]
    not artifact_fingerprint_recorded
}

violations contains sprintf("no artifact_creation_reported event for '%v' with a human-readable name", [artifact_name]) if {
    not artifact_human_name_recorded
}

violations contains "git_commit_info.sha1 is missing — artifact must be linked to its source commit" if {
    not git_commit_recorded
}

violations contains "git_commit_info.url is missing — a repository reference URL must be recorded" if {
    not repo_url_recorded
}

violations contains "origin_url is missing or empty — a CI build log URL must be recorded" if {
    not build_url_recorded
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

output := {
    "allow": allow,
    "violations": violations,
}
