# actions

Reusable GitHub Actions workflow used by kosli-demo Org repos to build a repo's
docker image securely and attest it for compliance.

`secure-docker-build.yml` builds the image from a `Dockerfile` (via
`docker/build-push-action`), pushes it to `ghcr.io`, then runs the compliance
attestations (shared via the `attest-and-evaluate` composite action).

## What the workflow does

- Build and push the image to `ghcr.io`, with `provenance: mode=max` and
  `sbom: true` so buildx produces SLSA provenance and an SPDX SBOM.
- Attest the image's build provenance and its SBOM to GitHub (sigstore) and to
  Kosli.
- Distill `provenance-facts` and `sbom-facts` from the raw sigstore bundle and
  SPDX document (a Kosli trail policy can only read structured custom
  attestation data, not the raw blobs) and attest each to Kosli.
- Evaluate the provenance against the `SDLC-CTRL-0002` (SLSA provenance) rego
  policy and the SBOM against the `SDLC-CTRL-0004` (dependency management) rego
  policy, then attest each compliance decision to Kosli as
  `provenance-decision` and `sbom-decision`.

The real image digest is the fingerprint for every attestation and decision, so
the Kosli artifact fingerprint, the GitHub/sigstore SLSA subject digest, and the
digest an environment snapshot reports are all the same value.

### Facts / decision model

`kosli evaluate trail` exposes only structured custom-attestation data to rego,
never the raw sigstore or SPDX blobs. So for each control the workflow:

1. distills the raw evidence into a small rego-friendly facts contract with a
   `.jq` filter (`provenance-facts.jq`, `sbom-facts.jq`),
2. attests those facts with `kosli attest custom`,
3. evaluates the control's rego policy over the trail, and
4. attests the compliance decision with `kosli attest decision --for-control`.

The `.jq` distill filter is the single source of truth shared between the
workflow and each control's rego tests.

## Controls

- `SDLC-CTRL-0002/` : `slsa-provenance.rego` + `provenance-facts.jq` + `tests/`.
  Checks the SLSA provenance predicate/build type, that the builder and source
  repo are trusted (prefixes are passed as params: the kosli-demo builder is
  `https://github.com/kosli-demo/actions/.github/workflows/` and the source repo
  prefix is `https://github.com/kosli-demo/`), and that the provenance subject
  digest and source commit match the artifact fingerprint and trail commit.
- `SDLC-CTRL-0004/` : `sbom.rego` + `sbom-facts.jq` + `sbom-overrides.*.json` +
  `sbom-overrides.schema.json` + `tests/`. Checks that the SPDX SBOM is a
  non-empty, well-formed inventory with a real dependency graph, and that every
  package has a concrete version and a resolvable purl. A per-service overrides
  allow-list (`sbom-overrides.<kosli_reference_name>.json`) can waive named
  per-package checks; a missing file means no waivers (fail toward
  non-compliance). kosli-demo callers pass `artifact` as the reference name, so
  `sbom-overrides.artifact.json` is the relevant list.

Before building, the workflow runs these controls' own rego policy tests as a
build gate (the `test-policies` job runs `make test-provenance test-sbom`), so a
broken policy fails the build early. The Kosli attestations are made only when
`attest_to_kosli` is true (typically on `main`).

## Typical use

```yml
name: Main

...

jobs:
  setup:
    ...

  build:
    needs: [setup]
    uses: kosli-demo/actions/.github/workflows/secure-docker-build.yml@main
    with:
      checkout_repository: ${{ github.repository }}
      checkout_ref: ${{ github.sha }}
      checkout_fetch_depth: 1
      image_name: ${{ needs.setup.outputs.image_name }}   # eg ghcr.io/kosli-demo/base
      image_tag: ${{ needs.setup.outputs.image_tag }}
      kosli_host: ${{ inputs.kosli_host }}
      kosli_flow: ${{ needs.setup.outputs.kosli_flow }}
      kosli_trail: ${{ needs.setup.outputs.kosli_trail }}
      kosli_reference_name: artifact
    secrets:
      kosli_api_token: ${{ inputs.kosli_api_token || secrets.kosli_api_token }}
```

## Versioning

The example above pins `@main`. To pin a release tag instead, list the available
tags with `git tag`. To create a new one:

```shell
git tag -a v0.0.6 -m "Some message"
git push origin v0.0.6
```
