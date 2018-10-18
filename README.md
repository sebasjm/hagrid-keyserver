Garbage Pile
============

Garbage Pile is a verifying OpenPGP key server. When a new key is uploaded a
token is sent to each user ID via email. This token can be used to verify the
user ID. Keys can be queried by their verified user IDs (exact match) and their
primary keys fingerprint. Key can be deleted by clicking a link send to all
user IDs.

Quick Start
-----------

Building Garbage Pile required a working [Rust _nightly_ toolchain](https://rust-lang.org).

```bash
cargo build
```

The key server uses the filesystem to store keys, user IDs and tokens. To run
it, supply the absolute path to where you want the database to live and the
absolute path to the template directory.

```bash
cargo run -- /var/garbage/ `pwd`/templates
```

This will spawn a web server listening on port 8080.

Usage
-----

While Garbage Piles URL scheme is meant to be machine readable, it's not a REST API. The following URLs are handled.

- `POST /keys` uploads a new key.

- `GET /keys?fpr=<base 64 fingerprint>` retrieves the key with the given
  fingerprint. The fingerprint is encoded using the [URL-safe
  variant](https://docs.rs/base64/0.9.3/base64/enum.CharacterSet.html) of base
  64 (`-` and `_` instead of `+` and `/`).

- `GET /keys?uid=<base 64 user ID>` retrieves the key with the given user ID. Only
  exact matches are accepted. The user ID is encoded using the [URL-safe
  variant](https://docs.rs/base64/0.9.3/base64/enum.CharacterSet.html) of base
  64 (`-` and `_` instead of `+` and `/`).

- `GET verify/<Token>` verifies a user ID using a token string send by email.

- `GET delete/<base 64 fingerprint>` requests deletion of the key with the given
  fingerprint. The fingerprint is encoded using the [URL-safe
  variant](https://docs.rs/base64/0.9.3/base64/enum.CharacterSet.html) of base
  64 (`-` and `_` instead of `+` and `/`).

- `GET confirm/<Token>` confirms a keys deletion request using a token string send
  by email.
