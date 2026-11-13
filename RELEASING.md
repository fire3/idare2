# Releasing idare2

This is the maintainer checklist for publishing `idare2` to TestPyPI and PyPI.
The project builds with [hatchling](https://hatch.pypa.io/) and publishes from
GitHub Actions with [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
so no long-lived PyPI API tokens are stored in the repository.

## One-time setup

1. Create accounts on [PyPI](https://pypi.org/account/register/) and
   [TestPyPI](https://test.pypi.org/account/register/), and enable 2FA on both.
2. In the GitHub repository, create two environments under
   **Settings -> Environments**:
   - `pypi` — this is the production gate. For a solo project you do **not**
     need a second reviewer. Choose one of these:
     - Leave **Required reviewers** empty. Publishing is still gated by the
       GitHub Release action and the `v*` tag rule below.
     - Or add yourself as the only required reviewer and leave **Prevent
       self-review** unchecked. GitHub lets you approve your own deployment,
       which gives you an extra confirmation click without needing another
       person.
     In either case, set **Deployment branches and tags** to
     **Selected branches and tags** -> **Tag** -> `v*`, so only release tags
     can deploy to `pypi`. Optionally add a short **Wait timer** (for example,
     5 minutes) if you want a cooling-off period before upload.
   - `testpypi` — no approval needed. It can stay unrestricted so you can
     test from branches.
3. Register the trusted publishers:
   - PyPI: <https://pypi.org/manage/account/publishing/>
     - PyPI project name: `idare2`
     - Owner: `fire3`
     - Repository name: `idare2`
     - Workflow name: `publish.yml`
     - Environment name: `pypi`
   - TestPyPI: <https://test.pypi.org/manage/account/publishing/>
     - Same values, except environment name: `testpypi`
4. Confirm that the distribution name `idare2` is still available:
   <https://pypi.org/project/idare2/>. It was available when this file was
   written.
5. Do **not** add `PYPI_API_TOKEN` or `TEST_PYPI_API_TOKEN` repository secrets.
   Trusted Publishing replaces them with short-lived OIDC credentials.

> **Solo maintainer tip:** Required reviewers are optional. If you add yourself
> as the only reviewer, keep **Prevent self-review** unchecked; otherwise no
> one can approve the deployment. The `v*` tag restriction is usually the more
> useful safety net for a personal project.

The workflow file name registered with PyPI must stay `publish.yml`. If you
rename it, update both trusted publishers.

## Versioning

`idare2` follows [Semantic Versioning](https://semver.org/). The single source
of truth is `__version__` in `src/idare2/__init__.py`. `pyproject.toml` reads
that value through hatchling (`dynamic = ["version"]`), so do not duplicate the
version in another file.

For each release:

1. Choose the next version, for example `0.1.2` or `0.2.0`.
2. Update `src/idare2/__init__.py`.
3. Move the entries in `CHANGELOG.md` from `Unreleased` to the new version and
   date.
4. Regenerate the self-hosted README badges:

   ```bash
   uv run tools/update_badges.py
   ```

   This updates `assets/badges/pypi.svg` from `__version__`, and the Python and
   license badges from `pyproject.toml`. The CI badge stays dynamic and is
   served by GitHub Actions.
5. Update version or dependency examples in the README and docs if needed.

## Local checks

```bash
# Create/refresh the development environment with test, lint, and build tools.
uv sync --group dev

# The default test suite is offline and fast.
uv run pytest

# Optional IDA-backed suites.  Install idalib into .venv first; use
# --no-sync so uv does not replace the idalib-provided idapro package.
uv run --no-sync pytest -m real_ida
uv run --no-sync pytest -m parity
uv run --no-sync pytest -m arch_matrix

# Lint.
uv run ruff check .

# Build the sdist and the wheel in isolated environments.
rm -rf dist/
uv build

# Validate metadata and README rendering.
uv run twine check dist/*
```

Inspect the artifacts before uploading:

```bash
unzip -p dist/idare2-*.whl '*/METADATA' | sed -n '1,60p'
tar -tzf dist/idare2-*.tar.gz | head -40
```

The wheel must contain the `idare2/` package and the `idare2`/`ir2` entry
points. The metadata should show `License-Expression: MIT`,
`Requires-Python: >=3.11`, `Requires-Dist: ida-nexus...`, and the license file.

Test the wheel in a clean environment:

```bash
python -m venv /tmp/idare2-wheel-test
/tmp/idare2-wheel-test/bin/pip install --no-deps dist/idare2-*.whl
/tmp/idare2-wheel-test/bin/idare2 -v
/tmp/idare2-wheel-test/bin/python -m idare2 -v
```

`idare2 -v` should work without IDA installed because IDA imports are lazy.

## TestPyPI dry run

Always test the release on TestPyPI first. TestPyPI is a separate index with
separate accounts and API tokens.

Manual upload with a TestPyPI API token:

```bash
# Create a token at https://test.pypi.org/manage/account/#api-tokens
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-...   # TestPyPI token
uv run twine upload --repository testpypi dist/*
```

Or run the **Publish to PyPI** workflow manually with `target: testpypi`
(**Actions -> Publish to PyPI -> Run workflow**). That job uses the `testpypi`
environment and Trusted Publishing.

Verify the TestPyPI install:

```bash
python -m venv /tmp/idare2-testpypi
/tmp/idare2-testpypi/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  'idare2==0.1.2'
/tmp/idare2-testpypi/bin/idare2 -v
```

The extra index is required because the runtime dependency `ida-nexus` lives on
PyPI, not TestPyPI.

## Publish to PyPI

1. Commit the version bump and changelog:

   ```bash
   git add src/idare2/__init__.py CHANGELOG.md README.md
   git commit -m "release: v0.1.2"
   ```

2. Tag and push:

   ```bash
   git tag -a v0.1.2 -m "idare2 0.1.2"
   git push origin main
   git push origin v0.1.2
   ```

3. Create a GitHub release for the tag:

   ```bash
   gh release create v0.1.2 --title "idare2 0.1.2" --notes-from-tag
   ```

   Publishing the release triggers `.github/workflows/publish.yml`, which
   builds the distributions and uploads them through the `pypi` environment.

4. If you added yourself as a required reviewer, approve the deployment in the
   GitHub Actions run (leave **Prevent self-review** unchecked). If you left
   required reviewers empty, the job runs immediately. The `pypi` environment's
   `v*` tag rule still prevents a branch build from publishing by accident.

   If you run the workflow manually with `target: pypi`, select the release tag
   in the **Use workflow from** dropdown; the `pypi` environment's `v*` rule
   rejects branch refs.

5. Verify the release:

   ```bash
   python -m pip index versions idare2
   python -m pip install --upgrade idare2
   idare2 -v
   ```

   Also check <https://pypi.org/project/idare2/> and the PEP 740 attestations
   attached to the uploaded files.

If the workflow is unavailable, the manual fallback is:

```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-...   # PyPI token
uv run twine upload dist/*
```

## Troubleshooting

- **`400 File already exists`**: PyPI versions are immutable. Bump the version;
  you cannot re-upload the same filename.
- **`invalid-publisher` or trusted-publishing errors**: confirm the PyPI
  publisher uses workflow `publish.yml`, environment `pypi`, owner `fire3`, and
  repository `idare2`, and that the publishing job has `id-token: write`.
- **License metadata error**: build with `hatchling>=1.27`, which is already
  required in `pyproject.toml`, and keep `license = "MIT"` plus
  `license-files = ["LICENSE"]`.
- **README rendering problems**: run `uv run twine check dist/*`. PyPI renders
  Markdown/reStructuredText only, and relative links do not work there.
- **TestPyPI cannot find `ida-nexus`**: install with
  `--extra-index-url https://pypi.org/simple/` as shown above.
- **The name is taken**: choose a different distribution name, update
  `[project].name`, the import package if appropriate, badges, URLs, and the
  trusted-publisher registration before the first upload.
