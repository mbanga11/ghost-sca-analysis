### What happened

When a pnpm lockfile contains a runtime dependency entry (for example `node@runtime:22.23.4`, which pnpm writes when `devEngines.runtime` is set), Syft fails to parse the YAML document containing it and catalogs **zero packages from that document**. The only signal is an entry under `files[].unknowns` in the JSON output; nothing is shown in the default CLI output, so the SBOM silently comes back nearly empty.

On a real project (Ghost CMS v6.74.0, lockfile written by pnpm 12.16.1), the dependency document holds ~2,759 packages and Syft reports 0 of them.

### What you expected to happen

The packages in the document are cataloged. The runtime entry itself could be skipped or modeled separately, but it shouldn't cause every other package in the document to be dropped.

### Steps to reproduce

Minimal `pnpm-lock.yaml` (one normal package plus one runtime entry, using the exact entry shape from a real lockfile, trimmed to one variant):

```yaml
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      is-number:
        specifier: 7.0.0
        version: 7.0.0
    devDependencies:
      node:
        specifier: runtime:22.23.4
        version: runtime:22.23.4

packages:

  is-number@7.0.0:
    resolution: {integrity: sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==}
    engines: {node: '>=0.12.0'}

  node@runtime:22.23.4:
    resolution:
      type: variations
      variants:
        - resolution:
            archive: tarball
            bin:
              node: bin/node
            integrity: sha256-whlBC+oK7Qjs+lhHo9ispORd1JSglPhsDYchE4Ngqck=
            type: binary
            url: https://nodejs.org/download/release/v22.23.4/node-v22.23.4-aix-ppc64.tar.gz
          targets:
            - cpu: ppc64
              os: aix

snapshots:

  is-number@7.0.0: {}

  node@runtime:22.23.4: {}
```

```bash
mkdir repro && cp pnpm-lock.yaml repro/
SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true syft dir:repro -q -o json > out.json
jq '[.artifacts[] | select(.type=="npm")] | length' out.json                  # 0, expected 1
jq -r '.files[] | select(.unknowns) | .unknowns[]' out.json
```

Unknowns output:

```
javascript-lock-cataloger: failed to parse pnpm-lock.yaml document 0: failed to unmarshal pnpm v9 lockfile: yaml: unmarshal errors:
  line 29: cannot unmarshal !!seq into string
```

Line 29 is the `- resolution:` item under `variants:`. Removing the `node@runtime` entries from `packages:` and `snapshots:` makes the same file return 1 package with no error.

### Anything else we need to know?

- Likely cause: the v9 lockfile model seems to expect `resolution` values to be strings (e.g. `integrity`), but a `type: variations` resolution contains a `variants` list.
- Multi-document lockfiles (pnpm 11+ writes a leading `---` document for pnpm itself): only the document containing the runtime entry is lost. On Ghost v6.74.0's real lockfile, Syft returns 15 packages (the pnpm self-install document) instead of 2,774; with the two runtime entries removed, it returns 2,774.
- Real-world file: `pnpm-lock.yaml` at tag `v6.74.0` of https://github.com/TryGhost/Ghost
- Another tool hit the same entry shape: aspect-build/rules_js#3060.
- Suggestion: a visible warning when a lockfile document fails to parse would have made this much easier to catch.

### Environment

- Syft 1.57.0 (also reproduced on 1.56.0)
- macOS, Apple Silicon (arm64)
- pnpm lockfile `lockfileVersion: '9.0'`, written by pnpm 12.16.1
