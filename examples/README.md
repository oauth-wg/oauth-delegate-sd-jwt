# Examples

Worked example included by `draft-ietf-oauth-delegate-sd-jwt.md`.

## Regenerating

```sh
python -m pip install 'cryptography>=42'
python examples/generate.py
```

The generator signs with RFC 6979 deterministic ECDSA, derives its demonstration
keys from fixed integers, and anchors all timestamps to a fixed epoch, so a
re-run reproduces the committed files byte for byte. A non-empty `git diff`
after running it means an input changed.

`generate.py` self-verifies before writing: ES256 signatures at every layer,
disclosure digests, chained `sd_hash` values, `typ` values, chain boundaries,
the checkout/transaction binding, and that each Verifier-specific presentation
omits the other Verifier's disclosure. It exits non-zero if any check fails.

## Layout

`01/` holds one chain, presented two ways.

| File | Contents |
| :--- | :--- |
| `sd_jwt_header.json` | Issuer-signed JWT protected header (`typ: sd+jwt`) |
| `sd_jwt_payload.json` | Issuer-signed JWT payload |
| `issuer_disclosures.md` | Disclosure for the Issuer-signed JWT |
| `sd_jwt_issuance.txt` | SD-JWT as issued to the Holder |
| `kb_sd_jwt_header.json` | KB-SD-JWT+KB protected header (`typ: kb-sd-jwt+kb`) |
| `kb_sd_jwt_payload.json` | KB-SD-JWT+KB payload signed by the Holder |
| `delegate_payload.json` | Delegate Payload carried by that KB-SD-JWT+KB |
| `delegate_disclosures.md` | Delegate Payload disclosure and its two claim disclosures |
| `dsd_jwt_delegation.txt` | dSD-JWT delegated to the Delegate Holder |
| `presentation_kb_header.json` | Terminal KB-SD-JWT protected header (`typ: kb+sd-jwt`) |
| `presentation_payment.txt` | dSD-JWT presented to the payment network |
| `presentation_payment_kb_payload.json` | Terminal KB-SD-JWT payload for that presentation |
| `presentation_payment_delegate_payload.json` | Its Delegate Payload |
| `presentation_checkout.txt` | dSD-JWT presented to the merchant |
| `presentation_checkout_delegate_payload.json` | Its Delegate Payload |

Both presentations reuse the same terminal protected header, so
`presentation_kb_header.json` covers each of them.

## Caveats

Demonstration keys are derived from small integers and must not be used outside
this example. Timestamps are anchored rather than current, so the example's
`exp` values are evaluated against the anchored epoch.

Claim names and `vct` values below the `delegate_payload` level are illustrative
and are not defined by this specification. The example is shaped like a payment
delegation because that is the motivating use case in the draft's Introduction,
but the structures are **not** canonical to AP2, Verifiable Intent, or any other
payment protocol, and are not intended to track one. The `vct` values use an
`example.` prefix to make that explicit.
