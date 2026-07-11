# Distill an SPDX 2.3 JSON document (produced by `docker buildx ... --sbom`, via
# syft) into the small facts contract that sbom.rego evaluates.
# A Kosli trail policy cannot read the raw SPDX blob; only this distilled JSON,
# attested with `kosli attest custom --attestation-data`, is visible to rego.
#
# The SPDX document-root package (the DESCRIBES target of SPDXRef-DOCUMENT, ie
# the image itself) is not a dependency and legitimately has no version or purl,
# so it is excluded from the packages inventory.
#
# syft records a package's real license in licenseDeclared and leaves
# licenseConcluded as NOASSERTION, so licenseDeclared is used as the fallback.
#
# Output contract:
#   {spec_version, created, creators, relationship_count,
#    packages: [{name, version, license, purl}]}
([
  .relationships[]?
  | select(.relationshipType == "DESCRIBES" and .spdxElementId == "SPDXRef-DOCUMENT")
  | .relatedSpdxElement
]) as $roots
| {
  spec_version: (.spdxVersion // ""),
  created: (.creationInfo.created // ""),
  creators: (.creationInfo.creators // []),
  relationship_count: ((.relationships // []) | length),
  packages: [
    (.packages // [])[]
    | select(.SPDXID as $id | ($roots | index($id)) == null)
    | {
        name: (.name // ""),
        version: (.versionInfo // ""),
        license: (
          (.licenseConcluded // "NOASSERTION") as $c
          | (if ($c == "NOASSERTION" or $c == "NONE" or $c == "") then (.licenseDeclared // "") else $c end)
        ),
        purl: ([ (.externalRefs // [])[] | select(.referenceType == "purl") | .referenceLocator ][0] // "")
      }
  ]
}
