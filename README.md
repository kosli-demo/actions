# actions/secure-docker-build.yml

- The secure-docker-build.yml workflow is used by kosli-demi Org repos in their Github Actions workflows.


Typical use is like this:

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
      image_name: ${{ needs.setup.outputs.image_name }}
      image_tag: ${{ needs.setup.outputs.image_tag }}
      kosli_host: ${{ inputs.kosli_host }}
      kosli_flow: ${{ needs.setup.outputs.kosli_flow }}
      kosli_trail: ${{ needs.setup.outputs.kosli_trail }}
      kosli_reference_name: artifact
    secrets:
      kosli_api_token: ${{ inputs.kosli_api_token || secrets.kosli_api_token }}

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
