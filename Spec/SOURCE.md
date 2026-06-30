# Spec source

This package implements **draft-sullivan-cfrg-raae** — "SEAL: Random-Access
Authenticated Encryption".

- **Source (rendered):** https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html
- **Source repo:** https://github.com/grittygrease/draft-sullivan-cfrg-raae
- **Snapshot date:** 2026-06-26 (draft `-latest`; individual draft, Informational,
  not yet CFRG-adopted)
- **Captured for this repo on:** 2026-06-29

## Why a vendored snapshot?

The draft is served from a living `-latest` URL with no frozen revision and is only
days old, so it will change. We pin to this dated snapshot as the conformance target.
On any spec refresh: re-capture the HTML, re-extract Appendix E vectors into
`Tests/RAAETests/Vectors/`, bump the snapshot date here, and re-run the test suite.

## Vectors

The Appendix E test vectors are the conformance oracle for every stage. They are
extracted (once, from this snapshot) into `Tests/RAAETests/Vectors/*.json`.

> TODO (Stage 1): download the HTML snapshot into `Spec/draft-2026-06-26.html` and
> extract Appendix E vectors to JSON. Left out of the initial commit to avoid
> vendoring a large HTML blob before the extraction tooling exists.
