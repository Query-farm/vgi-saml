# VGI SAML notebooks

[01 · A valid signature is one piece of evidence](01_a_valid_signature_is_one_piece_of_evidence.ipynb) separates XML parsing, signature mathematics, reference digests, assertion coverage and independently supplied signer context. It uses real VGI SQL over committed synthetic test vectors and retains all input rows.

## Run

Install [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The complete `notebooks/` directory also runs independently of this checkout:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

Initial setup downloads Python dependencies, the VGI community extension and the pinned native worker release. Analysis is local. No Rust toolchain, locally built worker, identity provider, credentials or private token data is needed. The release was executed on macOS Apple silicon; other available platform archives are listed on the worker's release page.

In VS Code select `notebooks/.venv/bin/python` and set the notebook working directory to `notebooks/`. Other Jupyter editors can register it:

```sh
uv run --project notebooks --frozen python -m ipykernel install --user --name vgi-saml-notebooks --display-name 'Python (vgi-saml notebooks)'
```

Restart and run all after changing the parameter. Connection and analytical SQL stay visible; imports, plotting, interpretation-generation source, assertions and cleanup are folded. Saved output embeds both charts.

## Experiment

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"INCLUDE_EC_SIGNER":true}' \
  --output-dir notebooks/validation/ec-in-inventory
```

The default excludes the EC fixture certificate from the synthetic inventory. Including it changes only inventory membership and the resulting review category. Reset to false for the saved default.

Overrides require a separate destination. The runner rejects unknown parameter names and writes a notebook only after a successful execution, preserving saved outputs on failure. Experiment copies include relative branding, fixtures, helpers and environment files. Logs, review charts and experiment copies are Git-ignored.

## Worker and fixture provenance

The visible literal `ATTACH` uses `github-auto://Query-farm/vgi-saml@v0.4.0`. VGI downloads, verifies and caches that platform release. Haybarn 2.0.0rc11 and the notebook dependencies are pinned in the independent lockfile. Upgrading requires changing the explicit release and reexecuting both parameter settings.

The eight files in `fixtures/` are unchanged copies from this repository's [test/data at 1baf314](https://github.com/Query-farm/vgi-saml/tree/1baf3149f23d752f890d05f96841b585bca224e0/test/data): five XML messages, one base64 representation, and two certificate SHA-256 fingerprint files. Their [original generator](https://github.com/Query-farm/vgi-saml/blob/1baf3149f23d752f890d05f96841b585bca224e0/crates/saml-core/tests/vectors/_generate.py) uses signxml/lxml and generated RSA/EC keys. Regeneration creates new key material, so the committed fixtures are the reproducible input; no private keys are included here. SQL adds malformed text and a NULL row. No live SAML exchange occurs.

The declared inventory is test data supplied from the separate fingerprint files, not trust inferred from a message. All identities, certificates and changed/wrapped messages are synthetic worker validation fixtures. File-level SHA-256 provenance is listed in `fixtures/manifest.json`.

## Reading the evidence

Five of the eight records have passing signature mathematics. The changed-content fixture still fails the reference digest; the wrapping fixture retains a valid digest and signature but contains two assertions, with the first decoded assertion different from the referenced one. The unsigned and malformed fixtures demonstrate that an empty anomaly list cannot establish validity. The audit preserves NULL input separately.

The matrix uses an em dash for unavailable or inapplicable checks, while the raw SQL display keeps the worker's exact output. The second chart assigns one explicit, ordered review category per input and retains zero-count categories. Its labels summarize this limited audit, not an authentication verdict. Adding the EC certificate moves one record from outside-inventory to consistent-with-listed-signer; cryptographic and parsing evidence stay fixed.

The assertion/reference join is a diagnostic for these assertion-signed fixtures. It includes the input record key, so repeated assertion IDs across files do not cross-match. It is not a general signature-coverage algorithm for response signatures, duplicate IDs, transforms or every SAML profile.

The worker's signature mathematics uses the embedded certificate. This example does not evaluate a full trust chain, certificate revocation, SAML Conditions time windows, recipient, audience, request correlation or replay. A stolen key whose certificate remains listed also matches the inventory. A matching fingerprint cannot detect that compromise by itself, and the notebook does not authorize a login. See [XML Signature core validation](https://www.w3.org/TR/xmldsig-core/#sec-CoreValidation) for the separate reference and signature checks.

## Validation

The default completed in 2.5 seconds; the detached directory experiment completed in 15.0 seconds. Both passed 12 SQL checks and the eight-record reconciliation. Four chart renderings and three runner preservation guards were reviewed; parsed evidence and assertion-reference displays are identical across settings. All eight fixture files match the original source and provenance hashes.

Source validation passed 38 Rust tests, 79 SQL assertions in five cases, the locked release build, Clippy, rustfmt and warning-clean rustdoc. Notebook Ruff and structural review passed. The unchanged source metadata gate (`vgi-lint-check==2.5.0`, executed examples and AI checks) returned exit 2: score 96/100, one VGI417 warning for oversized `saml.main` metadata, zero errors or informational findings. This pre-existing metadata issue is documented separately from the successful notebook execution. Worker source, test vectors, Cargo manifests and root lockfile remain unchanged.

Official Query.Farm Strata Sun and VGI artwork is copied unchanged from the approved assets. Linked Query.Farm branding appears at the top and final bottom.
