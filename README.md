Hagrid
======

Hagrid is a verifying OpenPGP key server. When a new key is uploaded a
token is sent to each user ID via email. This token can be used to verify the
user ID. Keys can be queried by their verified user IDs (exact match) and their
primary keys fingerprint. Key can be deleted by clicking a link send to all
user IDs.

Quick Start
-----------

Building Hagrid required a working [Rust _nightly_
toolchain](https://rust-lang.org). The key server uses the filesystem to store
keys, user IDs and tokens. To run it, supply the absolute path to where you
want the database to live and the absolute path to the template directory.

```bash
cargo run -- `pwd`/dist
```

This will spawn a web server listening on port 8080.

Usage
-----

While Hagrids URL scheme is meant to be machine readable, it's not a REST API. The following URLs are handled.

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

Building
--------

Hagrid consists of a Rust and a NPM project. While the web server is
implemented in Rust, HTML templates and CSS is bundled using NPM and Webpack.
Building the Rust part requires a working nightly Rust toolchain. The
easiest way to get the toolchain is to download [rustup](https://rustup.rs).
After rustup is installed, get the nightly compiler and tools:

```bash
rustup default nightly
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

Bundling the web assets requires npm 8 or later. After you have npm installed
fetch all dependencies and build the assets:

```bash
npm install
npm run build
```

The web assets are placed in `dist/`. To deploy the key server copy all
directories under `public/` to a writable location. Then start the server with
the _absolute_ path to the directory as argument:

```bash
mkdir /var/hagrid
cp -R dist/* /var/hagrid
hagrid /var/hagrid
```

This will spawn the server in foreground, listening on `0.0.0.0:8080`. The
`--listen` argument can be used to change port and listen address. The server
will put all keys and runtime data under the base folder (`/var/hagrid`
in the above example).

Community
---------

We're in `##hagrid` on Freenode.
