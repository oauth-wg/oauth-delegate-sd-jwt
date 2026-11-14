# Examples

Worked example included by `draft-ietf-oauth-delegate-sd-jwt.md`, plus an
independent verifier for it.

```sh
python -m pip install 'cryptography>=42'

python examples/generate.py                                 # (re)generate 01/
python examples/verify.py                                   # verify 01/ independently
python -m unittest discover -s examples -p 'test_*.py'      # negative tests
```

All three run standalone. `verify.py` and the tests read only the committed
files, so neither needs `generate.py` to have run first.

## Generating

`generate.py` produces every artifact under `01/` and self-checks before
writing: ES256 signatures at each layer, disclosure digests, Array Disclosure
wrapping, chained `sd_hash` values, `typ` values at each chain position, chain
boundaries, and that each Verifier-specific presentation omits the other's
disclosure. It exits non-zero on any failure.

### Determinism

Signatures use RFC 6979 deterministic ECDSA, keys are derived from fixed
integers, and timestamps are anchored to a fixed epoch. Re-running therefore
reproduces the committed files byte for byte:

```sh
python examples/generate.py && git diff --exit-code examples/01
```

A non-empty diff means an input changed. This matters for an example whose
whole point is a chain of hashes: without determinism every regeneration
rewrites every `sd_hash` and the files cannot be reviewed as a diff.

## Verifying independently

`verify.py` exists because `generate.py` cannot check its own serialization. A
self-check that recomputes a digest using the same helper that produced it will
agree with itself even when both are wrong. `verify.py` shares nothing with the
generator:

* it imports no generator code and reads none of its variables;
* it reparses the tokens from the wire form in `01/*.txt`, removing only the
  presentational line breaks;
* it re-derives the `sd_hash` input by re-joining the parsed components, rather
  than reusing the strings the generator hashed;
* it never reconstructs a token from the generation algorithm;
* it uses no private key.

### Trust anchors and the `cnf` chain

`01/trust_anchors.json` holds the only two public keys a Verifier must know out
of band: the Issuer key, and the merchant key used by the application-level
check. Every other key is reached through the chain itself.

The Issuer-signed JWT's `cnf` gives the key that must verify the first
KB-SD-JWT; that KB-SD-JWT's `cnf` gives the key that must verify the next
component, and so on. Replacing any `cnf` therefore breaks the following
signature, which is what makes the delegation relationship load-bearing rather
than decorative.

`cnf` for a KB-SD-JWT+KB lives in the **base KB-SD-JWT payload**, not in the
Delegate Payload — see the caveat below on draft alignment.

### What `verify.py` checks

| Area | Checks |
| :--- | :--- |
| JWS | three-segment structure, `alg` is `ES256`, unsecured and symmetric algorithms rejected, signature verified against the key from the preceding `cnf` |
| `typ` | `sd+jwt`, `kb-sd-jwt+kb` for every non-final component, `kb+sd-jwt` or `kb-sd-jwt+kb` for the final one |
| Disclosures | RFC 9901 decoding, digest recomputation, `_sd` membership, Array Disclosure `{"...": digest}` form, exactly one disclosed `delegate_payload` element |
| Binding | `sd_hash` or `issuer_jwt_hash` recomputed from the serialized predecessor; both presentations bound to different Verifier-specific serializations |
| Delegation | `cnf` to next-signer correspondence, `aud` and `nonce` present per step, optional expected-audience pinning |
| Validity | `iat`/`exp` evaluated at the anchored epoch, and the monotonic narrowing of `exp` and `nbf` across the chain |
| Structure | one empty component per boundary, no `~~~`, dSD-JWT distinguished from dSD-JWT+KB, final component placement |
| Selective disclosure | the payment presentation discloses only the payment claim, the checkout presentation only the checkout claim |
| Application | the two presentations reference the same transaction digest, the amount is within the delegated maximum, line items are within the delegated allow-list |

The application checks are kept in separate functions. They exercise this
example's own content and are **not** normative requirements of Delegate SD-JWT.

Checks raise `VerificationError` rather than using `assert`, so `python -O`
does not disable them.

## Negative tests

`test_verify.py` mutates the serialized tokens — the committed bytes, not any
generator variable — and asserts the verifier rejects them: tampered `sd_hash`,
tampered disclosure values, tampered signatures, wrong `typ`, unsecured `alg`,
mismatched `cnf`, a KB-SD-JWT+KB with no `cnf`, swapped per-Verifier
disclosures, a chain assembled from the other Verifier's component, bare
digests in `delegate_payload`, broken `~` boundaries, truncated chains,
unexpected `aud`, and expired components.

Signature verification runs before the semantic checks, so editing a signed
claim is reported as a signature failure. These tests therefore assert that the
mutation is rejected, and the semantic rules that tampering cannot reach
(Array Disclosure form, boundary grouping, digest recomputation, `typ` per
position) are covered by direct tests of those functions.

## Layout

| File | Contents |
| :--- | :--- |
| `generate.py` | Deterministic generator and self-check |
| `verify.py` | Independent verifier |
| `test_verify.py` | Negative tests |
| `01/trust_anchors.json` | Issuer and merchant public JWKs |
| `01/sd_jwt_header.json` | Issuer-signed JWT protected header (`typ: sd+jwt`) |
| `01/sd_jwt_payload.json` | Issuer-signed JWT payload |
| `01/issuer_disclosures.md` | Disclosure for the Issuer-signed JWT |
| `01/sd_jwt_issuance.txt` | SD-JWT as issued to the Holder |
| `01/kb_sd_jwt_header.json` | KB-SD-JWT+KB protected header (`typ: kb-sd-jwt+kb`) |
| `01/kb_sd_jwt_payload.json` | KB-SD-JWT+KB payload, including the security claims |
| `01/delegate_payload.json` | Delegate Payload carried by that KB-SD-JWT+KB |
| `01/delegate_disclosures.md` | Delegate Payload disclosure and its two claim disclosures |
| `01/dsd_jwt_delegation.txt` | dSD-JWT delegated to the Delegate Holder |
| `01/presentation_kb_header.json` | Terminal KB-SD-JWT protected header (`typ: kb+sd-jwt`) |
| `01/presentation_payment.txt` | dSD-JWT presented to the payment network |
| `01/presentation_payment_kb_payload.json` | Terminal KB-SD-JWT payload for that presentation |
| `01/presentation_payment_delegate_payload.json` | Its Delegate Payload |
| `01/presentation_checkout.txt` | dSD-JWT presented to the merchant |
| `01/presentation_checkout_delegate_payload.json` | Its Delegate Payload |

Both presentations reuse the same terminal protected header, so
`presentation_kb_header.json` covers each of them.

## Caveats

**Draft alignment.** These artifacts place `cnf` and the other security claims
in the base KB-SD-JWT payload, following
[PR #15](https://github.com/oauth-wg/oauth-delegate-sd-jwt/pull/15). Until that
PR merges, the Terms and Definitions entry for KB-SD-JWT+KB on `main` still
says the Delegate Payload carries `cnf`, so the example and that entry disagree.
The `## Examples` section of the draft and everything under `examples/` follow
PR #15; nothing here changes a normative requirement.

**Demonstration values.** Keys are derived from small integers and must not be
used outside this example. Timestamps are anchored rather than current, so the
example's `exp` values are evaluated against the anchored epoch.

**Application content.** Claim names and `vct` values below the
`delegate_payload` level are illustrative and are not defined by this
specification. The example is shaped like a payment delegation because that is
the motivating use case in the draft's Introduction, but the structures are
**not** canonical to AP2, Verifiable Intent, or any other payment protocol, and
are not intended to track one. The `vct` values use an `example.` prefix to
make that explicit.
