__Disclosure for `Delegate Payload (array element)`:__

```
SHA-256 Hash: RgUgNYLKYnEY4jNXn29W0cxxc3TVTXaqNj-iToQLQIg
Disclosure:
WyJkZW1vLWwyLXBheWxvYWQiLHsiX3NkIjpbIkhjbFFZRmZSVGs1Z0M2QmZYZVZvQlR1
LTB6eFg4ZHNhNE1za1MyTWtpN0EiLCItNHdfck5BVzRoZks2Z0ZnR2ZRQWlTalFmSHFT
N3JFdlUzOHdnLUYybmw0Il0sImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHki
OiJFQyIsIngiOiJCSlMtcGdEUTlrenlZMXBKdXMyX2VJRnkyT3R5Q0hnazhJNkZUWE9P
WExrIiwieSI6InlEemVLWUZGaFZGWGVEbmYySkl0anUyZTBVeVVfMmlPcVhrTHUtWG5K
Rk0ifX0sInZjdCI6Imh0dHBzOi8vZXhhbXBsZS50ZXN0L2RlbGVnYXRpb24ifV0
Contents:
[
  "demo-l2-payload",
  {
    "_sd": [
      "HclQYFfRTk5gC6BfXeVoBTu-0zxX8dsa4MskS2Mki7A",
      "-4w_rNAW4hfK6gFgGfQAiSjQfHqS7rEvU38wg-F2nl4"
    ],
    "cnf": {
      "jwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "BJS-pgDQ9kzyY1pJus2_eIFy2OtyCHgk8I6FTXOOXLk",
        "y": "yDzeKYFFhVFXeDnf2JItju2e0UyU_2iOqXkLu-XnJFM"
      }
    },
    "vct": "https://example.test/delegation"
  }
]
```

__Disclosure for `payment_mandate`:__

```
SHA-256 Hash: HclQYFfRTk5gC6BfXeVoBTu-0zxX8dsa4MskS2Mki7A
Disclosure:
WyJkZW1vLXBheW1lbnQtc2FsdCIsInBheW1lbnRfbWFuZGF0ZSIseyJhbGxvd2VkX3Bh
eWVlcyI6WyJtZXJjaGFudC5leGFtcGxlLnRlc3QiXSwiY25mIjp7Imp3ayI6eyJjcnYi
OiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkJKUy1wZ0RROWt6eVkxcEp1czJfZUlGeTJP
dHlDSGdrOEk2RlRYT09YTGsiLCJ5IjoieUR6ZUtZRkZoVkZYZURuZjJKSXRqdTJlMFV5
VV8yaU9xWGtMdS1YbkpGTSJ9fSwicGF5bWVudF9hbW91bnQiOnsiY3VycmVuY3kiOiJK
UFkiLCJtYXhfYW1vdW50IjoxNTAwMH0sInZjdCI6ImV4YW1wbGUucGF5bWVudC5tYW5k
YXRlIn1d
Contents:
[
  "demo-payment-salt",
  "payment_mandate",
  {
    "allowed_payees": [
      "merchant.example.test"
    ],
    "cnf": {
      "jwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "BJS-pgDQ9kzyY1pJus2_eIFy2OtyCHgk8I6FTXOOXLk",
        "y": "yDzeKYFFhVFXeDnf2JItju2e0UyU_2iOqXkLu-XnJFM"
      }
    },
    "payment_amount": {
      "currency": "JPY",
      "max_amount": 15000
    },
    "vct": "example.payment.mandate"
  }
]
```

__Disclosure for `checkout_mandate`:__

```
SHA-256 Hash: -4w_rNAW4hfK6gFgGfQAiSjQfHqS7rEvU38wg-F2nl4
Disclosure:
WyJkZW1vLWNoZWNrb3V0LXNhbHQiLCJjaGVja291dF9tYW5kYXRlIix7ImFsbG93ZWRf
aXRlbXMiOlt7Im1heF9xdWFudGl0eSI6Miwic2t1IjoiU0tVLUJPT0stMDAxIn1dLCJh
bGxvd2VkX21lcmNoYW50cyI6WyJtZXJjaGFudC5leGFtcGxlLnRlc3QiXSwiY25mIjp7
Imp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkJKUy1wZ0RROWt6eVkx
cEp1czJfZUlGeTJPdHlDSGdrOEk2RlRYT09YTGsiLCJ5IjoieUR6ZUtZRkZoVkZYZURu
ZjJKSXRqdTJlMFV5VV8yaU9xWGtMdS1YbkpGTSJ9fSwidmN0IjoiZXhhbXBsZS5jaGVj
a291dC5tYW5kYXRlIn1d
Contents:
[
  "demo-checkout-salt",
  "checkout_mandate",
  {
    "allowed_items": [
      {
        "max_quantity": 2,
        "sku": "SKU-BOOK-001"
      }
    ],
    "allowed_merchants": [
      "merchant.example.test"
    ],
    "cnf": {
      "jwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "BJS-pgDQ9kzyY1pJus2_eIFy2OtyCHgk8I6FTXOOXLk",
        "y": "yDzeKYFFhVFXeDnf2JItju2e0UyU_2iOqXkLu-XnJFM"
      }
    },
    "vct": "example.checkout.mandate"
  }
]
```
