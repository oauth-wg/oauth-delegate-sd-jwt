#!/usr/bin/env python3
"""Generate and self-verify the worked dSD-JWT example used in the draft.

Deterministic: fixed demonstration keys and a fixed epoch, so re-running
reproduces the committed files byte for byte.

    python -m pip install 'cryptography>=42'
    python examples/generate.py

Demonstration keys are derived from small integers and MUST NOT be used
anywhere outside this example.
"""
import base64, hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

OUT = Path(__file__).resolve().parent / '01'
NOW = 1793602800  # fixed demonstration epoch

def js(v): return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
def b64(data): return base64.urlsafe_b64encode(data).decode().rstrip('=')
def un64(x): return base64.urlsafe_b64decode(x+'='*((-len(x))%4))
def digest(data): return b64(hashlib.sha256(data).digest())
def sd_hash(serialized): return digest(serialized.encode('ascii'))
def key(i): return ec.derive_private_key(i, ec.SECP256R1())  # DEMO ONLY, NEVER reuse
ISSUER, HOLDER, AGENT, MERCHANT = [key(i) for i in (1001, 1002, 1003, 1004)]

def jwk(k):
    pub = k.public_key().public_numbers()
    return {'kty':'EC','crv':'P-256','x':b64(pub.x.to_bytes(32,'big')),'y':b64(pub.y.to_bytes(32,'big'))}
def verify_key(k): return k.public_key()
def sign(header, payload, private):
    # RFC 6979 deterministic ECDSA, so re-running reproduces the committed bytes.
    hp=b64(js(header))+'.'+b64(js(payload))
    der=private.sign(hp.encode(),ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r,s=decode_dss_signature(der)
    return hp+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
def decode(jwt):
    h,p,s=jwt.split('.')
    return json.loads(un64(h)),json.loads(un64(p)),(h+'.'+p).encode(),un64(s)
def check(jwt, public, typ):
    h,p,data,signature=decode(jwt)
    assert h['typ']==typ and h['alg']=='ES256', (h['typ'], typ)
    assert len(signature)==64
    r=int.from_bytes(signature[:32],'big');s=int.from_bytes(signature[32:],'big')
    public.verify(encode_dss_signature(r,s),data,ec.ECDSA(hashes.SHA256()))
    assert p['iat'] <= NOW <= p['exp']
    return p

def disclosure(salt, name, value):
    enc=b64(js([salt,name,value]))
    return enc, digest(enc.encode('ascii'))

def array_disclosure(salt, value):
    enc=b64(js([salt,value]))
    return enc, digest(enc.encode('ascii'))

def array_digest(dig):
    # RFC 9901 represents a selectively disclosable array element as {"...": digest}.
    return {'...': dig}

# L1: Issuer-signed SD-JWT, cnf identifies the Holder, email selectively disclosable.
email_d,email_hash=disclosure('demo-email-salt','email','alice@example.test')
l1_payload={'iss':'https://issuer.example.test','sub':'user-42','iat':NOW,'exp':NOW+31536000,
            'vct':'https://example.test/credentials/card','cnf':{'jwk':jwk(HOLDER)},
            'pan_last_four':'4242','scheme':'example','_sd_alg':'sha-256','_sd':[email_hash]}
l1=sign({'alg':'ES256','typ':'sd+jwt','kid':'issuer-key-1'},l1_payload,ISSUER)
l1_present=l1+'~'+email_d+'~'

# L2: Holder delegates to the Delegate Holder. KB-SD-JWT+KB, so typ is "kb-sd-jwt+kb"
# and the Delegate Payload carries cnf. Two authorizations are separately disclosable.
# The vct values are illustrative only; they are not canonical structures of any
# payment protocol and are not intended to track one.
payment={'vct':'example.payment.mandate','payment_amount':{'currency':'JPY','max_amount':15000},
         'allowed_payees':['merchant.example.test'],'cnf':{'jwk':jwk(AGENT)}}
checkout={'vct':'example.checkout.mandate','allowed_merchants':['merchant.example.test'],
          'allowed_items':[{'sku':'SKU-BOOK-001','max_quantity':2}], 'cnf':{'jwk':jwk(AGENT)}}
pay_d,pay_hash=disclosure('demo-payment-salt','payment_mandate',payment)
checkout_d,checkout_hash=disclosure('demo-checkout-salt','checkout_mandate',checkout)
l2_delegate={'vct':'https://example.test/delegation','cnf':{'jwk':jwk(AGENT)},
             '_sd':[pay_hash,checkout_hash]}
l2_dp,l2_dp_hash=array_disclosure('demo-l2-payload',l2_delegate)
l2_payload={'iat':NOW,'exp':NOW+86400,'nonce':'holder-nonce-demo','aud':'https://agent.example.test',
            'sd_hash':sd_hash(l1_present),'_sd_alg':'sha-256',
            'delegate_payload':[array_digest(l2_dp_hash)]}
l2=sign({'alg':'ES256','typ':'kb-sd-jwt+kb','kid':'holder-key-1'},l2_payload,HOLDER)

# The Delegate Holder re-serializes L2 per Verifier, revealing only the relevant mandate.
l2_for_network=l2+'~'+l2_dp+'~'+pay_d+'~'
l2_for_merchant=l2+'~'+l2_dp+'~'+checkout_d+'~'
checkout_jwt=sign({'alg':'ES256','typ':'JWT','kid':'merchant-key-1'},
    {'iss':'https://merchant.example.test','iat':NOW,'exp':NOW+300,
     'items':[{'sku':'SKU-BOOK-001','quantity':1,'unit_price':12000}], 'currency':'JPY'},MERCHANT)
transaction_hash=digest(checkout_jwt.encode('ascii'))

l3_payment={'vct':'example.payment.mandate','payment_instrument':{'last_four':'4242'},
    'payment_amount':{'currency':'JPY','amount':12000},'payee':{'id':'merchant.example.test'},
    'transaction_id':transaction_hash}
l3_checkout={'vct':'example.checkout.mandate','checkout_jwt':checkout_jwt,
    'checkout_hash':transaction_hash,'line_items':[{'sku':'SKU-BOOK-001','quantity':1}]}

# L3: terminal KB-SD-JWT, so typ is "kb+sd-jwt".
def final(l2_presentation, audience, payload, salt):
    d, dh=array_disclosure(salt,payload)
    pl={'iat':NOW,'exp':NOW+300,'nonce':'agent-'+salt,'aud':audience,'sd_hash':sd_hash(l2_presentation),
        '_sd_alg':'sha-256','delegate_payload':[array_digest(dh)]}
    jwt=sign({'alg':'ES256','typ':'kb+sd-jwt','kid':'agent-key-1'},pl,AGENT)
    return jwt,d,pl
l3a,l3a_d,l3a_pl=final(l2_for_network,'https://network.example.test',l3_payment,'network')
l3b,l3b_d,l3b_pl=final(l2_for_merchant,'https://merchant.example.test',l3_checkout,'merchant')

# "~~" marks each SD-JWT / KB-SD-JWT boundary; the trailing "~" marks a dSD-JWT.
network=l1_present+'~'+l2_for_network+'~'+l3a+'~'+l3a_d+'~'
merchant=l1_present+'~'+l2_for_merchant+'~'+l3b+'~'+l3b_d+'~'
holder_to_agent=l1_present+'~'+l2+'~'+l2_dp+'~'+pay_d+'~'+checkout_d+'~'

def verify_disclosure(encoded, digest_expected):
    assert digest(encoded.encode('ascii'))==digest_expected
    return json.loads(un64(encoded))

def array_element_digest(element):
    # Every delegate_payload entry must be an Array Disclosure digest object,
    # not a bare digest string.
    assert isinstance(element, dict) and list(element)==['...'], element
    assert isinstance(element['...'], str)
    return element['...']

def verify_all():
    p1=check(l1,verify_key(ISSUER),'sd+jwt')
    assert email_hash in p1['_sd'];verify_disclosure(email_d,email_hash)
    p2=check(l2,verify_key(HOLDER),'kb-sd-jwt+kb')
    assert p1['cnf']['jwk']==jwk(HOLDER)
    assert p2['sd_hash']==sd_hash(l1_present)
    assert array_element_digest(p2['delegate_payload'][0])==l2_dp_hash
    dp=verify_disclosure(l2_dp,l2_dp_hash)[1]
    assert dp['cnf']['jwk']==jwk(AGENT)
    assert pay_hash in dp['_sd'] and checkout_hash in dp['_sd']
    assert verify_disclosure(pay_d,pay_hash)[1]=='payment_mandate'
    assert verify_disclosure(checkout_d,checkout_hash)[1]=='checkout_mandate'
    pa=check(l3a,verify_key(AGENT),'kb+sd-jwt')
    pb=check(l3b,verify_key(AGENT),'kb+sd-jwt')
    assert pa['aud']=='https://network.example.test' and pb['aud']=='https://merchant.example.test'
    assert pa['sd_hash']==sd_hash(l2_for_network)
    assert pb['sd_hash']==sd_hash(l2_for_merchant)
    assert verify_disclosure(
        l3a_d,array_element_digest(pa['delegate_payload'][0]))[1]['transaction_id']==transaction_hash
    assert verify_disclosure(
        l3b_d,array_element_digest(pb['delegate_payload'][0]))[1]['checkout_hash']==transaction_hash
    merchant_checkout=check(checkout_jwt,verify_key(MERCHANT),'JWT')
    assert merchant_checkout['currency']=='JPY'
    assert l3_payment['payment_amount']['amount']<=payment['payment_amount']['max_amount']
    assert l3_checkout['line_items'][0]['sku'] in [x['sku'] for x in checkout['allowed_items']]
    assert pay_d not in l2_for_merchant and checkout_d not in l2_for_network
    # Every chain boundary uses exactly one empty component.
    for chain in (holder_to_agent, network, merchant):
        assert '~~~' not in chain and chain.endswith('~')
    return True

assert verify_all()

OUT.mkdir(parents=True, exist_ok=True)
def wrap(s, n=68):
    return '\n'.join(s[i:i+n] for i in range(0, len(s), n))
def write(name, text): (OUT/name).write_text(text if text.endswith('\n') else text+'\n')
def write_json(name, obj): write(name, json.dumps(obj, indent=2, ensure_ascii=False))

def disclosures_md(items):
    out=[]
    for enc, dig in items:
        contents=json.loads(un64(enc))
        label=contents[1] if len(contents)==3 else 'Delegate Payload (array element)'
        out.append(f'__Disclosure for `{label}`:__\n\n```\nSHA-256 Hash: {dig}\n'
                   f'Disclosure:\n{wrap(enc)}\nContents:\n'
                   f'{json.dumps(contents, indent=2, ensure_ascii=False)}\n```\n')
    return '\n'.join(out)

write_json('sd_jwt_header.json', decode(l1)[0])
write_json('sd_jwt_payload.json', l1_payload)
write('issuer_disclosures.md', disclosures_md([(email_d,email_hash)]))
write('sd_jwt_issuance.txt', wrap(l1_present))

write_json('kb_sd_jwt_header.json', decode(l2)[0])
write_json('kb_sd_jwt_payload.json', l2_payload)
write_json('delegate_payload.json', l2_delegate)
write('delegate_disclosures.md', disclosures_md(
    [(l2_dp,l2_dp_hash),(pay_d,pay_hash),(checkout_d,checkout_hash)]))
write('dsd_jwt_delegation.txt', wrap(holder_to_agent))

write_json('presentation_kb_header.json', decode(l3a)[0])
write_json('presentation_payment_kb_payload.json', l3a_pl)
write_json('presentation_payment_delegate_payload.json', l3_payment)
write('presentation_payment.txt', wrap(network))
write_json('presentation_checkout_delegate_payload.json', l3_checkout)
write('presentation_checkout.txt', wrap(merchant))

print('PASS: ES256 signatures, disclosures, chained sd_hash values, typ values, '
      'chain boundaries, checkout binding and constraint checks')
