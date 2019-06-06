Hagrid
======

Hagrid is a verifying OpenPGP key server. When a new key is uploaded a
token is sent to each user ID via email. This token can be used to verify the
user ID. Keys can be queried by their verified user IDs (exact match) and their
primary keys fingerprint. Keys can be deleted by clicking a link send to all
user IDs.

License
-------

Hagrid is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hagrid is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
License for more details.

You should have received a copy of the GNU Affero General Public
License along with Hagrid.  If not, see
<https://www.gnu.org/licenses/>.

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

You can find instructions and API documentation at the running instance at
[https://keys.openpgp.org](keys.openpgp.org).

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
