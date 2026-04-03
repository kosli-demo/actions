# actions/secure-docker-build.yml

- The secure-docker-build.yml workflow is used by kosli-demi Org repos in their Github Actions workflows.
- There is a partner composite workflow called [download-artifact](https://github.com/kosli-demo/download-artifact) for downloading the docker-image created.


Typical use is like this:

```yml
name: Main

...

jobs:
  setup:
    ...
  
  build-image:
    needs: [setup]    
    uses: kosli-demo/actions/.github/workflows/secure-docker-build.yml@main
    with:
      checkout_repository: kosli-demo/golden-ledger
      checkout_ref: ${{ github.sha }}
      checkout_fetch_depth: 1
      image_name: ${{ needs.setup.outputs.ecr_registry }}/${{ needs.setup.outputs.service_name }}
      image_tag: ${{ needs.setup.outputs.image_tag }}
      image_build_args: |
        COMMIT_SHA=${{ github.sha }}
      kosli_flow: ${{ needs.setup.outputs.kosli_flow }}
      kosli_trail: ${{ needs.setup.outputs.kosli_trail }}
      kosli_reference_name: golden-ledger
      attest_to_kosli: ${{ github.ref == 'refs/heads/main' }}        
    secrets:
      kosli_api_token: ${{ secrets.KOSLI_API_TOKEN }}


  after-build-image:
    runs-on: ubuntu-latest
    needs: [build-image]
    steps:
      - name: Download docker image
        uses: kosli-demo/download-artifact@main
        with:
          image_digest: ${{ needs.build-image.outputs.digest }}
      ...
```

The @v0.0.5 refers to tags in this repo:

```shell
git tag

v0.0.1
v0.0.2
v0.0.3
v0.0.4
v0.0.5
```

To create a new tag:

```shell
git tag -a v0.0.6 -m "Some message"
git push origin v0.0.6
```
