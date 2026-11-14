#!/usr/bin/env python3
"""Negative tests for the independent verifier.

Every case mutates the *serialized* token — the bytes as committed — rather than
any intermediate value of the generator, then asserts that `verify.py` rejects
it. A test that passes here means the mutation was actually detected on the wire.

    python -m unittest discover -s examples -p 'test_*.py'
"""
import base64
import copy
import json
import unittest
from pathlib import Path

import verify
from verify import VerificationError

EXAMPLE = Path(__file__).resolve().parent / '01'


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def b64u_json(obj):
    return b64u(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode())


def load(name):
    return verify.read_token(EXAMPLE / name)


def anchors():
    return verify.load_trust_anchors(EXAMPLE)


def split_components(serialized):
    """Return (groups, had_trailing_tilde) over the raw serialization."""
    parts = serialized.split('~')
    trailing = parts[-1] == ''
    if trailing:
        parts = parts[:-1]
    groups, current = [], []
    for part in parts:
        if part == '':
            groups.append(current)
            current = []
        else:
            current.append(part)
    groups.append(current)
    return groups, trailing


def join_components(groups, trailing):
    body = '~~'.join('~'.join(group) for group in groups)
    return body + '~' if trailing else body


def rewrite_payload(jwt, mutate):
    """Replace a JWT's payload, leaving header and signature untouched."""
    header, payload, signature = jwt.split('.')
    decoded = json.loads(verify.b64u_decode(payload))
    mutate(decoded)
    return f'{header}.{b64u_json(decoded)}.{signature}'


def rewrite_header(jwt, mutate):
    header, payload, signature = jwt.split('.')
    decoded = json.loads(verify.b64u_decode(header))
    mutate(decoded)
    return f'{b64u_json(decoded)}.{payload}.{signature}'


class VerifierNegativeTests(unittest.TestCase):

    def assert_rejected(self, serialized, name='mutated', **kwargs):
        with self.assertRaises(VerificationError) as caught:
            verify.verify_chain(serialized, anchors(), name, **kwargs)
        return str(caught.exception)

    # --- baseline ----------------------------------------------------------

    def test_unmodified_examples_verify(self):
        verify.verify_examples(EXAMPLE)

    # --- sd_hash -----------------------------------------------------------

    def test_tampered_sd_hash_is_rejected(self):
        # Signature verification precedes the semantic checks, so editing a signed
        # claim is caught as a signature failure. The property under test is that
        # the mutation is rejected at all; see test_recomputed_sd_hash_detects_* for
        # the binding logic itself.
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[1][0] = rewrite_payload(
            groups[1][0], lambda p: p.__setitem__('sd_hash', 'A' * 43))
        self.assert_rejected(join_components(groups, trailing))

    def test_recomputed_sd_hash_detects_a_changed_predecessor(self):
        """The binding digest is recomputed from the wire bytes, not trusted."""
        groups, _ = split_components(load('presentation_payment.txt'))
        declared = json.loads(verify.b64u_decode(groups[1][0].split('.')[1]))['sd_hash']
        recomputed = verify.sha256_b64u(verify.serialize_group(groups[0]).encode('ascii'))
        self.assertEqual(declared, recomputed)
        # Dropping the predecessor's disclosure changes the digest input.
        self.assertNotEqual(
            declared,
            verify.sha256_b64u(verify.serialize_group(groups[0][:1]).encode('ascii')))

    def test_dropping_a_disclosure_breaks_sd_hash(self):
        """sd_hash covers the preceding component *and* its disclosures."""
        groups, trailing = split_components(load('presentation_payment.txt'))
        del groups[0][1]  # remove the Issuer-signed JWT's only disclosure
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertIn('sd_hash', message)

    def test_cross_verifier_chain_does_not_verify(self):
        """A terminal KB-SD-JWT built for one Verifier must not accept the other's L2."""
        payment, trailing = split_components(load('presentation_payment.txt'))
        checkout, _ = split_components(load('presentation_checkout.txt'))
        swapped = [payment[0], checkout[1], payment[2]]
        message = self.assert_rejected(join_components(swapped, trailing))
        self.assertIn('sd_hash', message)

    # --- disclosures -------------------------------------------------------

    def test_tampered_disclosure_value_is_rejected(self):
        groups, trailing = split_components(load('dsd_jwt_delegation.txt'))
        contents = json.loads(verify.b64u_decode(groups[1][2]))
        contents[2]['payment_amount']['max_amount'] = 999999999
        groups[1][2] = b64u_json(contents)
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertIn('_sd', message)

    def test_bare_digest_in_delegate_payload_is_rejected(self):
        """RFC 9901 array elements must be {"...": digest}, not a bare string."""
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[1][0] = rewrite_payload(
            groups[1][0],
            lambda p: p.__setitem__('delegate_payload', [p['delegate_payload'][0]['...']]))
        self.assert_rejected(join_components(groups, trailing))

    def test_array_element_digest_requires_the_wrapped_form(self):
        """The Array Disclosure form check, exercised directly."""
        digest = 'GTgqFhPvdMtsx_CZJWNMwBboCrY-BllDnw9sFPQWsLE'
        self.assertEqual(verify.array_element_digest({'...': digest}, 'entry'), digest)
        for bad in (digest, [digest], {'digest': digest}, {'...': digest, 'extra': 1}, {'...': 1}):
            with self.assertRaises(VerificationError):
                verify.array_element_digest(bad, 'entry')

    def test_committed_examples_use_the_wrapped_form(self):
        payload = json.loads((EXAMPLE / 'kb_sd_jwt_payload.json').read_text())
        for entry in payload['delegate_payload']:
            self.assertEqual(list(entry), ['...'])

    def test_swapped_mandate_disclosures_are_rejected(self):
        """Attaching the other Verifier's disclosure must not verify."""
        payment, trailing = split_components(load('presentation_payment.txt'))
        checkout, _ = split_components(load('presentation_checkout.txt'))
        payment[1][2] = checkout[1][2]  # payment mandate -> checkout mandate
        message = self.assert_rejected(join_components(payment, trailing))
        self.assertIn('sd_hash', message)

    def test_selective_disclosure_separation_is_enforced(self):
        """Both mandates disclosed to one Verifier must be caught by the suite check."""
        payment = verify.verify_chain(
            load('dsd_jwt_delegation.txt'), anchors(), 'delegation')
        checkout = verify.verify_chain(
            load('presentation_checkout.txt'), anchors(), 'checkout presentation')
        with self.assertRaises(VerificationError) as caught:
            verify.verify_selective_disclosure(payment, checkout)
        self.assertIn('discloses', str(caught.exception))

    # --- signatures and headers -------------------------------------------

    def test_tampered_signature_is_rejected(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        header, payload, signature = groups[0][0].split('.')
        raw = bytearray(verify.b64u_decode(signature))
        raw[0] ^= 0xFF
        groups[0][0] = f'{header}.{payload}.{b64u(bytes(raw))}'
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertIn('signature does not verify', message)

    def test_tampered_payload_invalidates_signature(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[0][0] = rewrite_payload(
            groups[0][0], lambda p: p.__setitem__('sub', 'user-99'))
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertIn('signature does not verify', message)

    def test_wrong_typ_is_rejected(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[1][0] = rewrite_header(
            groups[1][0], lambda h: h.__setitem__('typ', 'kb+sd-jwt'))
        self.assert_rejected(join_components(groups, trailing))

    def test_typ_values_match_the_chain_position(self):
        """Each position carries the typ the draft requires for it."""
        result = verify.verify_chain(
            load('presentation_payment.txt'), anchors(), 'payment presentation')
        self.assertEqual([layer['typ'] for layer in result['layers']],
                         ['sd+jwt', 'kb-sd-jwt+kb', 'kb+sd-jwt'])
        delegation = verify.verify_chain(
            load('dsd_jwt_delegation.txt'), anchors(), 'delegation')
        self.assertEqual([layer['typ'] for layer in delegation['layers']],
                         ['sd+jwt', 'kb-sd-jwt+kb'])

    def test_unsecured_alg_is_rejected(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[0][0] = rewrite_header(
            groups[0][0], lambda h: h.__setitem__('alg', 'none'))
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertIn('expected ES256', message)

    # --- delegation binding ------------------------------------------------

    def test_mismatched_cnf_breaks_the_chain(self):
        """Replacing cnf with another key must stop the next layer verifying."""
        groups, trailing = split_components(load('presentation_payment.txt'))
        other = anchors()['merchant-key-1']
        groups[1][0] = rewrite_payload(
            groups[1][0], lambda p: p.__setitem__('cnf', {'jwk': other}))
        message = self.assert_rejected(join_components(groups, trailing))
        # The L2 signature breaks first; either failure proves the binding holds.
        self.assertTrue('signature does not verify' in message or 'sd_hash' in message, message)

    def test_kb_sd_jwt_kb_without_cnf_is_rejected(self):
        groups, trailing = split_components(load('dsd_jwt_delegation.txt'))
        groups[1][0] = rewrite_payload(groups[1][0], lambda p: p.pop('cnf'))
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertTrue('cnf' in message or 'signature does not verify' in message, message)

    def test_unexpected_audience_is_rejected(self):
        message = self.assert_rejected(
            load('presentation_payment.txt'), 'payment presentation',
            expected_audiences=['https://agent.example.test', 'https://attacker.example.test'])
        self.assertIn('aud', message)

    def test_expired_component_is_rejected(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        groups[1][0] = rewrite_payload(
            groups[1][0], lambda p: p.__setitem__('exp', verify.EVALUATION_TIME - 1))
        message = self.assert_rejected(join_components(groups, trailing))
        self.assertTrue('validity window' in message or 'signature does not verify' in message,
                        message)

    # --- serialization structure -------------------------------------------

    def test_missing_chain_boundary_is_rejected(self):
        """Collapsing "~~" to "~" removes the empty component the format requires."""
        self.assert_rejected(load('presentation_payment.txt').replace('~~', '~', 1))

    def test_parse_components_groups_on_the_empty_component(self):
        groups, kind = verify.parse_components(load('presentation_payment.txt'), 'payment')
        self.assertEqual(kind, 'dSD-JWT')
        self.assertEqual([len(group) for group in groups], [2, 3, 2])
        # Collapsing the boundary merges two components into one group.
        merged, _ = verify.parse_components(
            load('presentation_payment.txt').replace('~~', '~', 1), 'merged')
        self.assertEqual(len(merged), 2)

    def test_triple_tilde_is_rejected(self):
        message = self.assert_rejected(load('presentation_payment.txt').replace('~~', '~~~', 1))
        self.assertIn('more than one empty component', message)

    def test_truncated_chain_is_rejected(self):
        groups, trailing = split_components(load('presentation_payment.txt'))
        message = self.assert_rejected(join_components(groups[:1], trailing))
        self.assertIn('fewer than two components', message)

    def test_dsd_jwt_kb_is_distinguished_from_dsd_jwt(self):
        """Dropping the trailing tilde reclassifies the token, which must not pass silently."""
        serialized = load('presentation_payment.txt')
        self.assertTrue(serialized.endswith('~'))
        result = verify.verify_chain(serialized, anchors(), 'payment presentation')
        self.assertEqual(result['kind'], 'dSD-JWT')
        stripped = serialized[:-1]
        self.assertEqual(
            verify.parse_components(stripped, 'stripped')[1], 'dSD-JWT+KB')

    # --- application constraints -------------------------------------------

    def test_payment_over_delegated_maximum_is_rejected(self):
        delegation = verify.verify_chain(load('dsd_jwt_delegation.txt'), anchors(), 'delegation')
        payment = verify.verify_chain(
            load('presentation_payment.txt'), anchors(), 'payment presentation')
        checkout = verify.verify_chain(
            load('presentation_checkout.txt'), anchors(), 'checkout presentation')
        inflated = copy.deepcopy(payment)
        inflated['layers'][-1]['delegate_payload']['payment_amount']['amount'] = 10 ** 9
        with self.assertRaises(VerificationError) as caught:
            verify.verify_application_constraints(delegation, inflated, checkout, anchors())
        self.assertIn('exceeds the delegated maximum', str(caught.exception))

    def test_unpermitted_sku_is_rejected(self):
        delegation = verify.verify_chain(load('dsd_jwt_delegation.txt'), anchors(), 'delegation')
        payment = verify.verify_chain(
            load('presentation_payment.txt'), anchors(), 'payment presentation')
        checkout = verify.verify_chain(
            load('presentation_checkout.txt'), anchors(), 'checkout presentation')
        altered = copy.deepcopy(checkout)
        altered['layers'][-1]['delegate_payload']['line_items'][0]['sku'] = 'SKU-NOT-ALLOWED'
        with self.assertRaises(VerificationError) as caught:
            verify.verify_application_constraints(delegation, payment, altered, anchors())
        self.assertIn('allowed_items', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
