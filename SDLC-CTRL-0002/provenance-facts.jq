# Distill a GitHub sigstore attestation bundle (produced by
# actions/attest-build-provenance) into the provenance-facts contract that
# SDLC-CTRL-0002 evaluates. A Kosli trail policy cannot read the raw bundle;
# only this distilled JSON, attested with `kosli attest custom
# --type provenance-facts --attestation-data`, is visible to rego.
#
# The SLSA v1 in-toto statement is base64-encoded inside .dsseEnvelope.payload;
# decode it, then flatten the fields the rego checks. The git source is the
# resolvedDependency whose uri begins "git+", carrying a gitCommit digest.
# Missing fields distil to "" so the rego (not this filter) decides compliance.
#
# Output contract:
#   {predicate_type, build_type, builder_id, subject_digest,
#    source_repo, source_ref, source_uri, source_git_commit, invocation_id}
(.dsseEnvelope.payload | @base64d | fromjson) as $stmt
| (
    $stmt.predicate.buildDefinition.resolvedDependencies // []
    | map(select((.uri // "") | startswith("git+")))
    | (.[0] // {})
  ) as $src
| {
    predicate_type:    ($stmt.predicateType // ""),
    build_type:        ($stmt.predicate.buildDefinition.buildType // ""),
    builder_id:        ($stmt.predicate.runDetails.builder.id // ""),
    subject_digest:    ($stmt.subject[0].digest.sha256 // ""),
    source_repo:       ($stmt.predicate.buildDefinition.externalParameters.workflow.repository // ""),
    source_ref:        ($stmt.predicate.buildDefinition.externalParameters.workflow.ref // ""),
    source_uri:        ($src.uri // ""),
    source_git_commit: ($src.digest.gitCommit // ""),
    invocation_id:     ($stmt.predicate.runDetails.metadata.invocationId // "")
  }
