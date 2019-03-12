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
cp Rocket.toml.dist Rocket.toml
cargo run --bin hagrid
```

This will spawn a web server listening on port 8080.

Hagrid uses `sendmail` for mailing, so you also need a working local mailer
setup.

Usage
-----

### HKP

Hagrid implements a subset of the [HKP][] protocol so that tools like
GnuPG and OpenKeychain can use it without modification.

[HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00

#### `GET /pks/lookup?op=get&options=mr&search=<QUERY>`

Returns an *ASCII Armored* key matching the query.  Query may be:

 - An exact email address query of the form `localpart@example.org`.
 - A hexadecimal representation of a long *KeyID* of either a primary
   key, or a subkey (`069C0C348DD82C19`, optionally prefixed by `0x`).
 - A hexadecimal representation of a *Fingerprint* of either a primary
   key, or a subkey (`8E8C33FA4626337976D97978069C0C348DD82C19`,
   optionally prefixed by `0x`).

Note that while the hexadecimal digits may use either case, using
upper case letters is more efficient with Hagrid.

#### `GET /pks/lookup?op=index&options=mr&search=<QUERY>`

Returns a [machine-readable list][] of keys matching the query.  Query may
have the forms detailed above.  Hagrid always returns either one or no
keys at all.

[machine-readable list]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-5.2

#### `POST /pks/add`

Keys may be submitted using a POST request to `/pks/add`, the body of
the request being a `application/x-www-form-urlencoded` query.
`keytext` must be the key to submit, either *ASCII Armored* or not.

#### Limitations

By design, Hagrid cannot (or intentionally chooses not to) implement
the full HKP protocol.  The main limitations are:

 - No support for `op=vindex`,
 - only exact matches for user IDs are returned (i.e. `exact=on` is
   always assumed),
 - the `fingerprint` variable is ignored,
 - the `nm` option is ignored,
 - `op=index` returns either one or no keys,
 - uploads are restricted to 1 MiB,
 - all packets that aren't public keys, user IDs or signatures are filtered out.

### VKS

Hagrid has its own URL scheme to fetch keys.

#### `GET /vks/v1/by-fingerprint/<FINGERPRINT>`

Retrieves the key with the given *Fingerprint*.  *Fingerprint* may
refer to the primary key, or any subkey.  Hexadecimal digits MUST be
uppercase, and MUST NOT be prefixed with `0x`.  The returned key is
*ASCII Armored*.

#### `GET /vks/v1/by-keyid/<KEY-ID>`

Retrieves the key with the given long *KeyID*.  *KeyID* may refer to
the primary key, or any subkey.  Hexadecimal digits MUST be uppercase,
and MUST NOT be prefixed with `0x`.  The returned key is *ASCII
Armored*.

#### `GET /vks/v1/by-email/<URL-encoded user ID>`

Retrieves the key with the given *User ID*.  Only exact matches are
accepted.  Lookup by *User ID* requires opt-in by the key's owner.
The returned key is *ASCII Armored*.

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

To deploy the key server copy all directories under `dist/` to a
writable location, and create a suitable configuration file.

```bash
mkdir /var/lib/hagrid
cp -R dist/* /var/lib/hagrid
cp Rocket.toml.dist /var/lib/hagrid/Rocket.toml
$EDITOR /var/lib/hagrid/Rocket.toml
/usr/bin/env --chdir=/var/lib/hagrid ROCKET_ENV=production hagrid
```

This will spawn the server in foreground.  The server will put all
keys and runtime data under the base folder (`/var/lib/hagrid` in the
above example).

Reverse Proxy
-------------

Hagrid is designed to defer lookups to reverse proxy server like Nginx
and Apache. The key database is a set of 3 directories with static
files in them.  The directory structure reflects Hagrids URL
scheme. This way, lookups via `/vks/v1/by-finingerprint`,
`/vks/v1/by-keyid`, and `/vks/v1/by-email` can be handled by (multiple)
simple HTTP server(s). A sample configuration for Nginx is part of the
repository (`nginx.conf`).

Community
---------

We're in `##hagrid` on Freenode.
