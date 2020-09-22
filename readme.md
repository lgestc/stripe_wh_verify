# stripe_wh_verify

## About

This crate implements webhook payload verification, in accordance with official [Stripe Docs](https://stripe.com/docs/webhooks/signatures).

## Troubleshoting

If perfectly valid payloads do not get accepted, make sure that json payload is decoded as utf-8.
