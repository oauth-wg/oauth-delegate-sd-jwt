#!/usr/bin/env python3
"""Independent verifier for the committed dSD-JWT examples.

This module deliberately shares nothing with `generate.py`: it imports none of
its code, reads none of its variables, and never reconstructs a token from the
generation algorithm. It reads the serialized tokens from disk, reparses them
from the wire form, and recomputes every digest itself. A serialization bug on
the generation side is therefore not mirrored here.

Trust anchors are the two public keys a Verifier would have to know out of band
(the Issuer and, for the application-level check, the merchant). Every other key
in the chain is reached through a `cnf` claim of the preceding component.

    python -m pip install 'cryptography>=42'
    python examples/verify.py

Exits 0 when every check passes and non-zero otherwise. Checks raise
VerificationError rather than using `assert`, so `python -O` does not disable
them.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = Path(__file__).resolve().parent
EXAMPLE = HERE / '01'

# The examples are generated with anchored timestamps, so temporal claims are
# evaluated against that epoch rather than the wall clock.
EVALUATION_TIME = 1793602800

KB_SD_JWT_KB = 'kb-sd-jwt+kb'
KB_SD_JWT = 'kb+sd-jwt'
SD_JWT = 'sd+jwt'


class VerificationError(Exception):
    """Raised when any check on a presented dSD-JWT fails."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)
    return condition


# --- JOSE primitives -------------------------------------------------------

def b64u_decode(segment):
    require(isinstance(segment, str) and segment != '', 'empty base64url segment')
    require('=' not in segment, 'base64url segment is padded')
    return base64.urlsafe_b64decode(segment + '=' * ((-len(segment)) % 4))


def json_decode_segment(segment, what):
    try:
        value = json.loads(b64u_decode(segment))
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError(f'{what} is not base64url-encoded JSON: {exc}') from exc
    require(isinstance(value, dict), f'{what} is not a JSON object')
    return value


def sha256_b64u(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')


def public_key_from_jwk(jwk, what):
    require(isinstance(jwk, dict), f'{what} is not a JWK object')
    require(jwk.get('kty') == 'EC', f'{what} has unsupported kty {jwk.get("kty")!r}')
    require(jwk.get('crv') == 'P-256', f'{what} has unsupported crv {jwk.get("crv")!r}')
    for member in ('x', 'y'):
        require(member in jwk, f'{what} is missing {member}')
    require('d' not in jwk, f'{what} contains private key material')
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64u_decode(jwk['x']), 'big'),
        int.from_bytes(b64u_decode(jwk['y']), 'big'),
        ec.SECP256R1(),
    )
    return numbers.public_key()


def verify_compact_jws(token, public_key, what):
    """Verify a compact JWS and return (header, payload)."""
    parts = token.split('.')
    require(len(parts) == 3, f'{what} is not a three-segment compact JWS')
    encoded_header, encoded_payload, encoded_signature = parts

    header = json_decode_segment(encoded_header, f'{what} protected header')
    payload = json_decode_segment(encoded_payload, f'{what} payload')

    require(header.get('alg') == 'ES256', f'{what} alg is {header.get("alg")!r}, expected ES256')

    signature = b64u_decode(encoded_signature)
    require(len(signature) == 64, f'{what} signature is not 64 bytes')
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    signing_input = f'{encoded_header}.{encoded_payload}'.encode('ascii')
    try:
        public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerificationError(f'{what} signature does not verify') from exc

    return header, payload


# --- RFC 9901 disclosures --------------------------------------------------

def decode_disclosure(encoded, what):
    try:
        contents = json.loads(b64u_decode(encoded))
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError(f'{what} is not a base64url-encoded JSON array: {exc}') from exc
    require(isinstance(contents, list), f'{what} is not a JSON array')
    require(len(contents) in (2, 3), f'{what} has {len(contents)} elements, expected 2 or 3')
    return contents, sha256_b64u(encoded.encode('ascii'))


def array_element_digest(element, what):
    """Return the digest of an RFC 9901 selectively disclosable array element."""
    require(isinstance(element, dict), f'{what} is not an object; a bare digest string is invalid')
    require(list(element) == ['...'], f'{what} must have exactly one member named "..."')
    require(isinstance(element['...'], str), f'{what} digest is not a string')
    return element['...']


# --- dSD-JWT serialization -------------------------------------------------

def read_token(path):
    """Read a committed example, removing only the presentational line breaks."""
    return path.read_text().replace('\n', '')


def parse_components(serialized, what):
    """Split a dSD-JWT or dSD-JWT+KB into its component groups.

    Returns (groups, kind) where each group is a list whose first element is a
    JWT and whose remaining elements are that component's disclosures, and kind
    is 'dSD-JWT' or 'dSD-JWT+KB'.
    """
    require('~' in serialized, f'{what} contains no tilde separator')
    require('~~~' not in serialized, f'{what} has a chain boundary with more than one empty component')

    parts = serialized.split('~')
    if parts[-1] == '':
        kind = 'dSD-JWT'
        parts = parts[:-1]
    else:
        kind = 'dSD-JWT+KB'

    groups, current = [], []
    for part in parts:
        if part == '':
            require(current, f'{what} has an empty component group')
            groups.append(current)
            current = []
        else:
            current.append(part)
    require(current, f'{what} ends with a chain boundary and no following component')
    groups.append(current)

    require(len(groups) >= 2, f'{what} has fewer than two components; not a delegated SD-JWT')
    for index, group in enumerate(groups):
        require(group[0].count('.') == 2, f'{what} component {index} does not start with a JWT')
    return groups, kind


def serialize_group(group):
    """Reproduce the bytes an sd_hash is computed over, per RFC 9901 Section 4.3.1."""
    return '~'.join(group) + '~'


# --- Chain verification ----------------------------------------------------

def verify_sd_jwt_disclosures(payload, disclosures, what):
    """Check that every presented disclosure is committed to in _sd."""
    declared = payload.get('_sd', [])
    require(isinstance(declared, list), f'{what} _sd is not an array')
    resolved = {}
    for encoded in disclosures:
        contents, dig = decode_disclosure(encoded, f'{what} disclosure')
        require(dig in declared,
                f'{what} presents a disclosure whose digest {dig} is not in _sd')
        require(len(contents) == 3, f'{what} object disclosure must have three elements')
        resolved[contents[1]] = contents[2]
    return resolved


def verify_delegate_payload(payload, group, what):
    """Resolve the single disclosed Delegate Payload of a KB-SD-JWT."""
    entries = payload.get('delegate_payload')
    require(isinstance(entries, list) and entries, f'{what} has no delegate_payload array')
    digests = [array_element_digest(entry, f'{what} delegate_payload entry') for entry in entries]

    disclosed = []
    for encoded in group[1:]:
        contents, dig = decode_disclosure(encoded, f'{what} disclosure')
        if dig in digests:
            require(len(contents) == 2,
                    f'{what} Delegate Payload disclosure must be an array disclosure')
            require(isinstance(contents[1], dict), f'{what} Delegate Payload is not an object')
            disclosed.append((contents[1], encoded, dig))

    require(len(disclosed) == 1,
            f'{what} discloses {len(disclosed)} delegate_payload elements, expected exactly one')
    delegate_payload, encoded, _ = disclosed[0]

    remaining = [d for d in group[1:] if d != encoded]
    return delegate_payload, remaining


def verify_chain(serialized, trust_anchors, what, expected_audiences=None):
    """Verify a presented dSD-JWT end to end and return a per-layer report."""
    groups, kind = parse_components(serialized, what)

    issuer_jwk = trust_anchors.get('issuer-key-1')
    require(issuer_jwk is not None, 'trust anchors do not contain the Issuer key')

    # --- Layer 1: the Issuer-signed SD-JWT, verified against the trust anchor.
    sd_jwt_group = groups[0]
    header, payload = verify_compact_jws(
        sd_jwt_group[0], public_key_from_jwk(issuer_jwk, 'Issuer trust anchor'), f'{what} SD-JWT')
    require(header.get('typ') == SD_JWT,
            f'{what} SD-JWT typ is {header.get("typ")!r}, expected {SD_JWT!r}')
    verify_sd_jwt_disclosures(payload, sd_jwt_group[1:], f'{what} SD-JWT')

    report = [{'layer': 'SD-JWT', 'typ': header.get('typ'), 'payload': payload}]

    previous_payload = payload
    previous_group = sd_jwt_group
    previous_exp = payload.get('exp')
    previous_nbf = payload.get('nbf')

    kb_groups = groups[1:]
    for index, group in enumerate(kb_groups):
        label = f'{what} KB-SD-JWT[{index}]'
        is_final = index == len(kb_groups) - 1

        # The signing key comes from the preceding component's cnf, never from a
        # fixture: this is what makes the delegation chain load-bearing.
        cnf = previous_payload.get('cnf')
        require(isinstance(cnf, dict) and 'jwk' in cnf,
                f'{label} predecessor has no cnf.jwk to verify this component against')
        signer = public_key_from_jwk(cnf['jwk'], f'{label} predecessor cnf.jwk')

        header, payload = verify_compact_jws(group[0], signer, label)
        typ = header.get('typ')
        if is_final and kind == 'dSD-JWT':
            require(typ in (KB_SD_JWT, KB_SD_JWT_KB),
                    f'{label} typ is {typ!r}, expected {KB_SD_JWT!r} or {KB_SD_JWT_KB!r}')
        else:
            require(typ == KB_SD_JWT_KB, f'{label} typ is {typ!r}, expected {KB_SD_JWT_KB!r}')

        # Per PR #15 a KB-SD-JWT+KB carries cnf in its base payload.
        if typ == KB_SD_JWT_KB:
            require(isinstance(payload.get('cnf'), dict) and 'jwk' in payload['cnf'],
                    f'{label} is a KB-SD-JWT+KB but its base payload has no cnf.jwk')

        # Binding to the preceding component, recomputed from the wire bytes.
        if 'sd_hash' in payload:
            expected = sha256_b64u(serialize_group(previous_group).encode('ascii'))
            require(payload['sd_hash'] == expected,
                    f'{label} sd_hash does not match the preceding component and its disclosures')
            binding = 'sd_hash'
        else:
            require('issuer_jwt_hash' in payload,
                    f'{label} has neither sd_hash nor issuer_jwt_hash')
            expected = sha256_b64u(previous_group[0].encode('ascii'))
            require(payload['issuer_jwt_hash'] == expected,
                    f'{label} issuer_jwt_hash does not match the preceding JWT')
            binding = 'issuer_jwt_hash'

        # Temporal claims, including the monotonic narrowing PR #15 requires.
        require('iat' in payload, f'{label} has no iat')
        require('exp' in payload, f'{label} has no exp')
        require(payload['iat'] <= EVALUATION_TIME <= payload['exp'],
                f'{label} is outside its validity window at the evaluation time')
        if previous_exp is not None:
            require(payload['exp'] <= previous_exp,
                    f'{label} exp is later than a preceding exp; validity must narrow')
        if 'nbf' in payload and previous_nbf is not None:
            require(payload['nbf'] >= previous_nbf,
                    f'{label} nbf is earlier than a preceding nbf; validity must narrow')

        require(isinstance(payload.get('aud'), str) and payload['aud'],
                f'{label} has no aud identifying the recipient of this delegation step')
        require(isinstance(payload.get('nonce'), str) and payload['nonce'],
                f'{label} has no nonce for this delegation step')
        if expected_audiences is not None:
            require(payload['aud'] == expected_audiences[index],
                    f'{label} aud is {payload["aud"]!r}, '
                    f'expected {expected_audiences[index]!r}')

        delegate_payload, claim_disclosures = verify_delegate_payload(payload, group, label)
        claims = verify_sd_jwt_disclosures(
            delegate_payload, claim_disclosures, f'{label} Delegate Payload')

        report.append({
            'layer': f'KB-SD-JWT[{index}]',
            'typ': typ,
            'binding': binding,
            'payload': payload,
            'delegate_payload': delegate_payload,
            'disclosed_claims': claims,
        })

        previous_payload = payload
        previous_group = group
        previous_exp = payload['exp']
        previous_nbf = payload.get('nbf', previous_nbf)

    return {'kind': kind, 'layers': report}


# --- Application-level checks ----------------------------------------------
# Not normative requirements of Delegate SD-JWT. These exercise the example's
# own application content, which this specification does not define.

def verify_application_constraints(delegation, payment, checkout, trust_anchors):
    delegated = delegation['layers'][-1]['disclosed_claims']
    require(set(delegated) == {'payment_mandate', 'checkout_mandate'},
            'the delegation should disclose both application mandates')

    pay_terminal = payment['layers'][-1]
    check_terminal = checkout['layers'][-1]

    pay_mandate = pay_terminal['delegate_payload']
    check_mandate = check_terminal['delegate_payload']

    require(pay_mandate.get('transaction_id') == check_mandate.get('checkout_hash'),
            'the two presentations do not reference the same transaction digest')

    merchant_jwk = trust_anchors.get('merchant-key-1')
    require(merchant_jwk is not None, 'trust anchors do not contain the merchant key')
    _, checkout_claims = verify_compact_jws(
        check_mandate['checkout_jwt'],
        public_key_from_jwk(merchant_jwk, 'merchant trust anchor'),
        'application checkout JWT')
    require(check_mandate['checkout_hash'] ==
            sha256_b64u(check_mandate['checkout_jwt'].encode('ascii')),
            'checkout_hash is not the digest of the presented checkout JWT')

    allowed = delegated['payment_mandate']['payment_amount']['max_amount']
    require(pay_mandate['payment_amount']['amount'] <= allowed,
            'the presented payment amount exceeds the delegated maximum')
    require(pay_mandate['payment_amount']['currency'] == checkout_claims['currency'],
            'the presented currency does not match the checkout')

    permitted = {item['sku'] for item in delegated['checkout_mandate']['allowed_items']}
    for line in check_mandate['line_items']:
        require(line['sku'] in permitted,
                f'line item {line["sku"]!r} is not among the delegated allowed_items')


def verify_selective_disclosure(payment, checkout):
    """Neither Verifier may receive the claim disclosed to the other."""
    pay_claims = set(payment['layers'][1]['disclosed_claims'])
    check_claims = set(checkout['layers'][1]['disclosed_claims'])
    require(pay_claims == {'payment_mandate'},
            f'the payment presentation discloses {sorted(pay_claims)}, expected only payment_mandate')
    require(check_claims == {'checkout_mandate'},
            f'the checkout presentation discloses {sorted(check_claims)}, expected only checkout_mandate')


# --- Entry point -----------------------------------------------------------

def load_trust_anchors(directory=EXAMPLE):
    return json.loads((directory / 'trust_anchors.json').read_text())


def verify_examples(directory=EXAMPLE):
    trust_anchors = load_trust_anchors(directory)

    issuance = read_token(directory / 'sd_jwt_issuance.txt')
    require(issuance.endswith('~'), 'the issued SD-JWT does not end with a tilde')
    require('~~' not in issuance, 'the issued SD-JWT should have no delegation boundary')

    delegation = verify_chain(
        read_token(directory / 'dsd_jwt_delegation.txt'), trust_anchors,
        'delegation', expected_audiences=['https://agent.example.test'])
    payment = verify_chain(
        read_token(directory / 'presentation_payment.txt'), trust_anchors,
        'payment presentation',
        expected_audiences=['https://agent.example.test', 'https://network.example.test'])
    checkout = verify_chain(
        read_token(directory / 'presentation_checkout.txt'), trust_anchors,
        'checkout presentation',
        expected_audiences=['https://agent.example.test', 'https://merchant.example.test'])

    for name, result in (('delegation', delegation), ('payment presentation', payment),
                         ('checkout presentation', checkout)):
        require(result['kind'] == 'dSD-JWT', f'{name} is a {result["kind"]}, expected a dSD-JWT')

    require(len(delegation['layers']) == 2, 'the delegation should have two components')
    require(len(payment['layers']) == 3, 'the payment presentation should have three components')
    require(len(checkout['layers']) == 3, 'the checkout presentation should have three components')

    # The two presentations are bound to different serializations of the same
    # KB-SD-JWT+KB, which is why a chain built for one does not verify at the other.
    pay_hash = payment['layers'][2]['payload']['sd_hash']
    check_hash = checkout['layers'][2]['payload']['sd_hash']
    require(pay_hash != check_hash,
            'the two terminal sd_hash values are identical; '
            'they must cover Verifier-specific serializations')

    verify_selective_disclosure(payment, checkout)
    verify_application_constraints(delegation, payment, checkout, trust_anchors)

    return delegation, payment, checkout


def main():
    try:
        verify_examples()
    except VerificationError as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: signatures, typ values, disclosures, Array Disclosure form, '
          'recomputed sd_hash bindings, cnf delegation chain, temporal narrowing, '
          'chain structure, selective disclosure separation and application constraints')
    return 0


if __name__ == '__main__':
    sys.exit(main())
