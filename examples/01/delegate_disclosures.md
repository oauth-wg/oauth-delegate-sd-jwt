__Disclosure for `Delegate Payload (array element)`:__

```
SHA-256 Hash: GTgqFhPvdMtsx_CZJWNMwBboCrY-BllDnw9sFPQWsLE
Disclosure:
WyJkZW1vLWwyLXBheWxvYWQiLHsiX3NkIjpbIm1Cck5VVlZMZk5zczdFbGNQVHJsWTZw
Nk5JMzVXTEM5NmhGU3BKVU1qZGMiLCI0d1M3aUwwdm9uZURjWVRySFRGSi01NG5YNng5
MllyeHhzWHBnMUpORkVJIl0sInZjdCI6Imh0dHBzOi8vZXhhbXBsZS50ZXN0L2RlbGVn
YXRpb24ifV0
Contents:
[
  "demo-l2-payload",
  {
    "_sd": [
      "mBrNUVVLfNss7ElcPTrlY6p6NI35WLC96hFSpJUMjdc",
      "4wS7iL0voneDcYTrHTFJ-54nX6x92YrxxsXpg1JNFEI"
    ],
    "vct": "https://example.test/delegation"
  }
]
```

__Disclosure for `payment_mandate`:__

```
SHA-256 Hash: mBrNUVVLfNss7ElcPTrlY6p6NI35WLC96hFSpJUMjdc
Disclosure:
WyJkZW1vLXBheW1lbnQtc2FsdCIsInBheW1lbnRfbWFuZGF0ZSIseyJhbGxvd2VkX3Bh
eWVlcyI6WyJtZXJjaGFudC5leGFtcGxlLnRlc3QiXSwicGF5bWVudF9hbW91bnQiOnsi
Y3VycmVuY3kiOiJKUFkiLCJtYXhfYW1vdW50IjoxNTAwMH0sInZjdCI6ImV4YW1wbGUu
cGF5bWVudC5tYW5kYXRlIn1d
Contents:
[
  "demo-payment-salt",
  "payment_mandate",
  {
    "allowed_payees": [
      "merchant.example.test"
    ],
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
SHA-256 Hash: 4wS7iL0voneDcYTrHTFJ-54nX6x92YrxxsXpg1JNFEI
Disclosure:
WyJkZW1vLWNoZWNrb3V0LXNhbHQiLCJjaGVja291dF9tYW5kYXRlIix7ImFsbG93ZWRf
aXRlbXMiOlt7Im1heF9xdWFudGl0eSI6Miwic2t1IjoiU0tVLUJPT0stMDAxIn1dLCJh
bGxvd2VkX21lcmNoYW50cyI6WyJtZXJjaGFudC5leGFtcGxlLnRlc3QiXSwidmN0Ijoi
ZXhhbXBsZS5jaGVja291dC5tYW5kYXRlIn1d
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
    "vct": "example.checkout.mandate"
  }
]
```
