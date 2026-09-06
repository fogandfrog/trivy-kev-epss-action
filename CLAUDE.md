# CLAUDE.md — trivy-kev-epss-action

Public, MIT-licensed composite GitHub Action and standalone CLI. It enriches a Trivy JSON report with CISA KEV membership and FIRST EPSS scores, renders a summary, and fails the workflow on exploitation evidence rather than on severity alone. Listed on the GitHub Marketplace as **Trivy KEV EPSS Gate**: https://github.com/marketplace/actions/trivy-kev-epss-gate.

## Layout and conventions

- `trivy_kev_epss.py` is the whole implementation: one file, Python 3.10 or newer, standard library only, PyYAML optional. Type hints everywhere. `action.yml` wraps it and passes every input through `INPUT_*` environment variables, never through the command line.
- Tests live in `tests/`, run offline against the fixtures in `tests/fixtures/`, and serve the KEV and EPSS feeds through `file://` URLs. `tests/live/` holds the lockfile the CI `live` job scans with a real Trivy against the real feeds.
- This repository is public and generic. Nothing organisation-specific goes in it: no private image names, clusters, hostnames or internal links.
- Every third-party action used in `.github/workflows/` is pinned by full commit SHA with the version in a trailing comment. Keep it that way; the README explains why.
- Markdown is GitHub Flavored, in English, with paragraphs left unwrapped.

## Checks

```bash
ruff check .
ruff format --check .
python -m pytest
```

Install `pytest`, `pyyaml` and `ruff` in whatever environment runs them. CI runs `lint`, `test` on Python 3.10 and 3.14, and `live` on every pull request; `live` also runs weekly to catch feed format drift.

## `action.yml` rules the Marketplace enforces

GitHub validates the metadata against the default branch when a release is published to the Marketplace, so a broken `action.yml` on `main` blocks publication even for an old tag.

- `name` must be unique across the Marketplace and must not contain a slash; the listing slug is derived from it.
- `description` must be under 125 characters.
- `branding.icon` and `branding.color` are required.
- A README must exist.

## Releasing a version

Consumers pin this action by commit SHA, so a release never moves an existing pin. The procedure:

1. Bump `version` in `pyproject.toml` in the release pull request and merge it.
2. Tag the merge commit with a signed annotated tag and move the major tag to it, then push both:

   ```bash
   git tag -s vX.Y.Z <sha> -m "vX.Y.Z"
   git tag -f -s v1 <sha> -m "v1 (moving major tag, currently vX.Y.Z)"
   git push origin vX.Y.Z
   git push -f origin v1
   ```

   The major tag is the only tag that ever moves. Never retag a published `vX.Y.Z`.
3. Create the GitHub release for the tag, not as a draft, with the SHA-pinned `uses:` line for the new commit and a changelog since the previous release, one line per commit:

   ```markdown
   - [`<short-hash>`](https://github.com/fogandfrog/trivy-kev-epss-action/commit/<short-hash>) Message (#PR)
   ```

   `gh release create vX.Y.Z --verify-tag --title vX.Y.Z --notes-file <file>` does this from the terminal.
4. Publish the version to the Marketplace. There is no API for this step; a release created from the terminal is not on the Marketplace until it is done in the browser:
   - open the release page and click **Edit release**;
   - the box **Publish this Action to the GitHub Marketplace** is pre-ticked for this repository, with the categories Security and Continuous integration already set; leave them;
   - press **Update release**;
   - confirm that https://github.com/marketplace/actions/trivy-kev-epss-gate shows the new version.

   A generic "We weren't able to create the release for you" with no field error means the metadata failed a Marketplace rule listed above; fix `action.yml` on `main` and retry the edit.
5. Update the pinned `uses:` examples in the README to the new commit SHA and version comment in a follow-up pull request.
