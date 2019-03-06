Hagrid
======

Hagrid is a verifying OpenPGP key server. When a new key is uploaded a
token is sent to each user ID via email. This token can be used to verify the
user ID. Keys can be queried by their verified user IDs (exact match) and their
primary keys fingerprint. Keys can be deleted by clicking a link send to all
user IDs.

Quick Start
-----------

Building Hagrid required a working [Rust _nightly_
toolchain](https://rust-lang.org). The key server uses the filesystem to store
keys, user IDs and tokens. To run it, supply the absolute path to where you
want the database to live and the absolute path to the template directory.

```bash
cargo run --bin hagrid -- dist
```

This will spawn a web server listening on port 8080.

Hagrid uses `sendmail` for mailing, so you also need a working local mailer
setup. The FROM field of the mails can be configured with the `-F` switch.

Usage
-----

### HKP

Hagrid implements basic HKP (`op=get` and `op=index`) so tools like GnuPG and
OpenKeychain can use it directly. The differences to SKS are

 - no support for `op=vindex`,
 - only exact matches for user IDs are returned (i.e. `exact=on` is
   always assumed),
 - `op=index` returns either one or no keys,
 - all packets that aren't public keys, user IDs or signatures are filtered out.

### VKS

Hagrid has it's own URL scheme to fetch keys, verify user IDs and delete keys.
It's meant to be machine readable, but it's not a REST API. The following URLs
are handled.

- `GET /vks/by-fingerprint/<FINGERPRINT>` retrieves the key with the given
  fingerprint.  Hexadecimal digits must be uppercase.
- `GET /vks/by-keyid/<KEY-ID>` retrieves the key with the given long key
  ID.  Hexadecimal digits must be uppercase.
- `GET /vks/by-email/<URL-encoded user ID>` retrieves the key with the given user
  ID. Only exact matches are accepted.
- `GET /vks/verify/<token>` verifies a user ID using a token string send by
  email.
- `GET /vks/delete/<fingerprint>` requests deletion of the key with the given
  fingerprint.
- `GET /vks/confirm/<token>` confirms a keys deletion request using a token
  string send by email.

Keys can also be fetched by their subkeys fingerprint and key
ID. Note: keys will show up even if no user IDs are verified.

Building
--------

Building Hagrid requires a working nightly Rust toolchain. The
easiest way to get the toolchain is to download [rustup](https://rustup.rs).
After rustup is installed, get the nightly compiler and tools:

```bash
cd hagrid
rustup override set nightly
```

The web server can now be built with the cargo command:

```bash
cargo build --release
```

After compilation a binary is placed in `target/release/` called
`hagrid`. The binary is linked statically and can be copied everywhere.

```bash
cp target/release/hagrid /usr/local/bin
```

To deploy the key server copy all
directories under `public/` to a writable location. Then start the server with
the _absolute_ path to the directory as argument:

```bash
mkdir /var/lib/hagrid
cp -R dist/* /var/lib/hagrid
hagrid /var/lib/hagrid
```

This will spawn the server in foreground, listening on `0.0.0.0:8080`. The
`--listen` argument can be used to change port and listen address. The server
will put all keys and runtime data under the base folder (`/var/lib/hagrid`
in the above example).

Reverse Proxy
-------------

Hagrid is designed to defer lookups to reverse proxy server like Nginx
and Apache. The key database is a set of 3 directories with static
files in them.  The directory structure reflects Hagrids URL
scheme. This way, lookups via `/vks/by-finingerprint`,
`/vks/by-keyid`, and `/vks/by-email` can be handled by (multiple)
simple HTTP server(s). A sample configuration for Nginx is part of the
repository (`nginx.conf`).

Community
---------

We're in `##hagrid` on Freenode.
