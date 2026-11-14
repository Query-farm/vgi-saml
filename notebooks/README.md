# SAML Forensics example

[01 · A valid signature is one piece of evidence](01_a_valid_signature_is_one_piece_of_evidence.ipynb)
retains the signature/reference/assertion/signer-context audit and adds root-message classification
and attribute multiplicity. It covers eight of thirteen public SQL surfaces in one coherent
workflow. All inputs are synthetic test vectors; the notebook does not authenticate a login.

Read saved results on GitHub or use **Open in Colab**, then Run All. A single downloaded notebook
installs the base shared tools and retrieves hash-verified fixtures. Actual hosted Colab is
untested; validation includes a fresh local Python 3.12 notebook-only environment with data,
plotting and kernel libraries already loaded.

## Run from this directory

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/) and internet for first-time Python/shared
package, community extension, fixture and native worker release downloads.

```sh
uv sync --locked --extra runner
uv run --locked --extra runner vgi-notebooks
```

The [shared package v0.3.24](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.24) supplies canonical branding, SVG presentation, isolated SQL setup and
atomic execution. Colab installs only its base package; local publication uses the optional
`[runner]` extra and independent `uv.lock`. The complete directory runs without its parent worker
checkout. No Rust toolchain, local worker build, identity provider, credentials or real token data
is required. Validation uses macOS arm64; the release page lists other available platform assets.

```sql
INSTALL vgi FROM community;
LOAD vgi;
SET TimeZone='UTC';
ATTACH 'saml' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-saml@v0.4.0');
```

VGI downloads, SHA-256-verifies and caches the platform release. The tag resolves to
`4ca77f71318b77a80ef2bede4be8bc56b48a253f`. Worker dependency compatibility belongs to that release;
no transitive overrides are added. Upgrade the explicit release and rerun both settings.
Haybarn 2.0.0rc11 is pinned separately in the notebook environment.

`connect(globals())` creates empty temporary SQL-secret storage, disables persistence and prevents
JupySQL's saved default-connection autoload. No credentials are required; cleanup closes the
connection and removes the temporary store. Existing secrets are not read or modified.

Optional local kernel:

```sh
uv run --locked --extra runner python -m ipykernel install --user \
  --name vgi-saml-notebooks --display-name 'Python (vgi-saml notebooks)'
```

Restart and Run All after editing. Parameters, setup, ATTACH and analytical SQL remain visible;
Python presentation source has folding metadata. Defaults retain native SVG plus committed image
links for GitHub. Experiments keep native SVG only; generated logs, exports and copies are ignored.

## Experiment

```sh
uv run --locked --extra runner vgi-notebooks \
  --parameters '{"INCLUDE_EC_SIGNER":true}' --output-dir validation/ec-in-inventory
```

The default leaves the EC certificate outside the authored signer inventory. Adding it changes
only that inventory membership and the ordered review category. Parsed subjects, signature math,
reference digests, structural flags, message kinds and claimed attributes must stay fixed.
A matching fingerprint does not repair changed content or authorize an identity. Restore false
for publication. The parameter accepts booleans only.

Overrides require a separate destination. Unknown parameters, source-overwriting paths and invalid
values fail without replacing the last successful default or experiment. Copies include portable
companions; no source checkout or user credentials accompany them.

## Fixture provenance

The eight original fixture files are unchanged copies from [test/data at 1baf314](https://github.com/Query-farm/vgi-saml/tree/1baf3149f23d752f890d05f96841b585bca224e0/test/data):
five XML messages, one base64 representation and two SHA-256 certificate fingerprint files.
The [original generator](https://github.com/Query-farm/vgi-saml/blob/1baf3149f23d752f890d05f96841b585bca224e0/crates/saml-core/tests/vectors/_generate.py)
uses signxml/lxml and generated RSA/EC keys. Regeneration creates new key material; committed fixture
bytes provide reproducibility. No private keys are included. SQL adds malformed text and NULL.
[manifest.json](fixtures/manifest.json) records source and file hashes, checked during setup.

The declared inventory comes from the separate fingerprint files, not trust inferred from a
message. Identities, certificates and changed/wrapped content are synthetic validation vectors.
No live SAML exchange, network identity lookup or authentication action occurs.

## Interpretation

The six recognizable messages all have Response roots, including changed, wrapped and unsigned
content. `message_type` provides context rather than a validity filter; malformed `unknown` and
missing NULL remain distinct. Five of eight inputs have passing signature mathematics, while the
changed-subject fixture still fails its reference digest. The wrapping fixture retains a valid
digest/signature but contains two assertions: the first decoded assertion differs from the
referenced one. An empty anomaly list does not establish validity for unsigned or malformed input.

The matrix distinguishes unavailable/inapplicable checks from false. Raw SQL retains exact worker
values. The ordered category chart keeps all eight inputs and zero-count categories. A category
such as “Consistent with listed signer” summarizes only the demonstrated checks, not a login verdict.

The assertion/reference join includes the input-record key, preventing repeated assertion IDs
across files from cross-matching. It is a diagnostic for these assertion-signed fixtures, not a
general coverage algorithm for response signatures, duplicate IDs or arbitrary transforms.

Attributes are one row per AttributeValue: the wrapped fixture doubles three rows to six while
still reducing to the same two distinct role values. `statement_idx` identifies statement order,
not an assertion ID or signature-reference key. Do not attach every flattened role to the first
decoded subject or treat deduplication as evidence that the source is unambiguous. Extracted claims
are values to investigate, not authorization.

Signature mathematics uses the embedded certificate. The notebook does not evaluate a full trust
chain, revocation, Conditions time windows, audience, recipient, request correlation, replay or
service-provider policy. A stolen key whose certificate remains listed also matches the inventory.
See [XML Signature core validation](https://www.w3.org/TR/xmldsig-core/#sec-CoreValidation) for the
separate reference and signature checks. These limits apply even if every displayed cell is green.

## Coverage and validation

[coverage.json](coverage.json) records eight of thirteen named SQL surfaces, with successful visible
SQL, result interpretation and editorial review. The complete runtime functions/tables/views
exports establish thirteen functions, zero physical tables and zero views. This exceeds the
seven-object target for a worker with more than ten surfaces. `conditions`, `authn`, `b64decode`,
`inflate` and `unwrap` remain explicitly uncovered; automatic transport normalization is not counted
as a separate invocation of those plumbing functions.

Current public source retains the same interface; differences add composed metadata/examples/tests
and correct an example expectation. Runtime/core behavior and dependencies are unchanged. Coverage
separates exact released-runtime demonstrations from current-interface compatibility review;
no current source build or runtime execution is claimed.

Both parameter settings execute with the actual native release. Validation retains the original
12 SQL checks and eight-record reconciliation, adds root-kind/attribute population controls,
checks all fixture hashes, compares unchanged evidence, tests runner preservation, reviews figures
and checks actual GitHub SVG rendering. The fresh preloaded notebook-only bootstrap is separate
from a hosted Colab test.

Existing green [source CI 43579874212](https://github.com/Query-farm/vgi-saml/actions/runs/43579874212)
is reused, including metadata, Rust/unit/proptest, SQL and audit jobs. No worker build, repeated
source suite or CI/container dispatch is performed for this notebook-only migration. The previous
local strict metadata run reported VGI417 overlong schema metadata (96/100, one warning); that
historical stricter result is retained separately from the green CI gate, not claimed rerun or
fixed here. Source, Cargo manifests/lock and original fixtures remain unchanged.
