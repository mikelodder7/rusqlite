# Support for SQLCipher is now available in [Rusqlite](https://github.com/rusqlite/rusqlite)

Use [Rusqlite](https://github.com/rusqlite/rusqlite) with SQLCipher support by adding this to your Cargo.toml:

```toml
[dependencies.rusqlite]
version = "0.23.1"
features = ["sqlcipher"]
```

# Rusqlcipher

[![Travis Build Status](https://api.travis-ci.org/jgallagher/rusqlite.svg?branch=master)](https://travis-ci.org/jgallagher/rusqlite)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/jgallagher/rusqlite?branch=master&svg=true)](https://ci.appveyor.com/project/jgallagher/rusqlite)
[![dependency status](https://deps.rs/repo/github/jgallagher/rusqlite/status.svg)](https://deps.rs/repo/github/jgallagher/rusqlite)
[![Latest Version](https://img.shields.io/crates/v/rusqlite.svg)](https://crates.io/crates/rusqlite)

Rusqlcipher is an ergonomic wrapper for using SQLCipher from Rust. It attempts to expose
an interface similar to [rust-postgres](https://github.com/sfackler/rust-postgres). View the full
[API documentation](http://docs.rs/rusqlite/).

```rust
extern crate rusqlcipher;
extern crate time;

use time::Timespec;
use rusqlcipher::Connection;

#[derive(Debug)]
struct Person {
    id: i32,
    name: String,
    time_created: Timespec,
    data: Option<Vec<u8>>
}

fn main() {
    let conn = Connection::open_in_memory().unwrap();

    conn.execute("CREATE TABLE person (
                  id              INTEGER PRIMARY KEY,
                  name            TEXT NOT NULL,
                  time_created    TEXT NOT NULL,
                  data            BLOB
                  )", &[]).unwrap();
    let me = Person {
        id: 0,
        name: "Steven".to_string(),
        time_created: time::get_time(),
        data: None
    };
    conn.execute("INSERT INTO person (name, time_created, data)
                  VALUES (?1, ?2, ?3)",
                 &[&me.name, &me.time_created, &me.data]).unwrap();

    let mut stmt = conn.prepare("SELECT id, name, time_created, data FROM person").unwrap();
    let person_iter = stmt.query_map(&[], |row| {
        Person {
            id: row.get(0),
            name: row.get(1),
            time_created: row.get(2),
            data: row.get(3)
        }
    }).unwrap();

    for person in person_iter {
        println!("Found person {:?}", person.unwrap());
    }
}
```

### SQLCipher
This work is based on [`rusqlite`](https://github.com/jgallagher/rusqlite) and [`SQLCipher`](https://github.com/mikelodder7/sqlcipher).
This package has precompiled SQLCipher to use OpenSSL 1.1.0 or newer and replaces the following three files in *libsqlcipher-sys/sqlite3/*: sqlite3.c, sqlite3.h, sqlite3ext.h. See [`openssl-sys`](https://crates.io/crates/openssl-sys) for information on compiling openssl. SQLCipher has been modified to use HMAC-SHA256 instead of the default HMAC-SHA1.

### Supported SQLite Versions

The base `rusqlcipher` package supports SQLite version 3.6.8 or newer. If you need
support for older versions, please file an issue. Some cargo features require a
newer SQLite version; see details below.

### Optional Features

Rusqlite provides several features that are behind [Cargo
features](http://doc.crates.io/manifest.html#the-features-section). They are:

* [`load_extension`](http://jgallagher.github.io/rusqlite/rusqlite/struct.LoadExtensionGuard.html)
  allows loading dynamic library-based SQLite3 extensions.
* [`backup`](http://jgallagher.github.io/rusqlite/rusqlite/backup/index.html)
  allows use of SQLite's online backup API. Note: This feature requires SQLite 3.6.11 or later.
* [`functions`](http://jgallagher.github.io/rusqlite/rusqlite/functions/index.html)
  allows you to load Rust closures into SQLite connections for use in queries.
  Note: This feature requires SQLite 3.7.3 or later.
* [`trace`](http://jgallagher.github.io/rusqlite/rusqlite/trace/index.html)
  allows hooks into SQLite's tracing and profiling APIs. Note: This feature
  requires SQLite 3.6.23 or later.
* [`blob`](http://jgallagher.github.io/rusqlite/rusqlite/blob/index.html)
  gives `std::io::{Read, Write, Seek}` access to SQL BLOBs. Note: This feature
  requires SQLite 3.7.4 or later.
* [`limits`](http://jgallagher.github.io/rusqlite/rusqlite/struct.Connection.html#method.limit)
  allows you to set and retrieve SQLite's per connection limits.
* `chrono` implements [`FromSql`](http://jgallagher.github.io/rusqlite/rusqlite/types/trait.FromSql.html)
  and [`ToSql`](http://jgallagher.github.io/rusqlite/rusqlite/types/trait.ToSql.html) for various
  types from the [`chrono` crate](https://crates.io/crates/chrono).
* `serde_json` implements [`FromSql`](http://jgallagher.github.io/rusqlite/rusqlite/types/trait.FromSql.html)
  and [`ToSql`](http://jgallagher.github.io/rusqlite/rusqlite/types/trait.ToSql.html) for the
  `Value` type from the [`serde_json` crate](https://crates.io/crates/serde_json).
* `bundled` uses a bundled version of sqlite3.  This is a good option for cases where linking to sqlite3 is complicated, such as Windows.
* `sqlcipher` looks for the SQLCipher library to link against instead of SQLite. This feature is mutually exclusive with `bundled`.

## Notes on building rusqlcipher and libsqlcipher-sys

`libsqlcipher-sys` is a separate crate from `rusqlcipher` that provides the Rust
declarations for SQLite's C API. By default, `libsqlcipher-sys` attempts to find a SQLite library that already exists on your system using pkg-config, or a
[Vcpkg](https://github.com/Microsoft/vcpkg) installation for MSVC ABI builds. 
`rusqlcipher` also depends on OpenSSL version 1.1.0 or above.

You can adjust this behavior in a number of ways:

* If you use the `bundled` feature, `libsqlcipher-sys` will use the
  [gcc](https://crates.io/crates/gcc) crate to compile SQLite from source and
  link against that. This source is embedded in the `libsqlcipher-sys` crate and
  is currently SQLite 3.15.2 (as of `rusqlcipher` 0.10.1 / `libsqlcipher-sys`
  0.7.1).  This is probably the simplest solution to any build problems. You can enable this by adding the following in your `Cargo.toml` file:
  ```
  [dependencies.rusqlcipher]
  version = "0.11.0"
  features = ["bundled"]
  ```
* You can set the `SQLITE3_LIB_DIR` to point to directory containing the SQLite
  library.
* Installing the sqlite3 development packages will usually be all that is required, but
  the build helpers for [pkg-config](https://github.com/alexcrichton/pkg-config-rs)
  and [vcpkg](https://github.com/mcgoo/vcpkg-rs) have some additional configuration
  options. The default when using vcpkg is to dynamically link. `vcpkg install sqlite3:x64-windows` will install the required library.

### Binding generation

We use [bindgen](https://crates.io/crates/bindgen) to generate the Rust
declarations from SQLite's C header file. `bindgen`
[recommends](https://github.com/servo/rust-bindgen#library-usage-with-buildrs)
running this as part of the build process of libraries that used this. We tried
this briefly (`rusqlcipher` 0.10.0, specifically), but it had some annoyances:

* The build time for `libsqlcipher-sys` (and therefore `rusqlcipher`) increased
  dramatically.
* Running `bindgen` requires a relatively-recent version of Clang, which many
  systems do not have installed by default.
* Running `bindgen` also requires the SQLite header file to be present.

As of `rusqlcipher` 0.1.0, we avoid running `bindgen` at build-time by shipping
pregenerated bindings for several versions of SQLite. When compiling
`rusqlcipher`, we use your selected Cargo features to pick the bindings for the
minimum SQLite version that supports your chosen features. If you are using
`libsqlcipher-sys` directly, you can use the same features to choose which
pregenerated bindings are chosen:

* `min_sqlite_version_3_6_8` - SQLite 3.6.8 bindings (this is the default)
* `min_sqlite_version_3_6_11` - SQLite 3.6.11 bindings
* `min_sqlite_version_3_6_23` - SQLite 3.6.23 bindings
* `min_sqlite_version_3_7_3` - SQLite 3.7.3 bindings
* `min_sqlite_version_3_7_4` - SQLite 3.7.4 bindings

If you use the `bundled` feature, you will get pregenerated bindings for the
bundled version of SQLite. If you need other specific pregenerated binding
versions, please file an issue. If you want to run `bindgen` at buildtime to
produce your own bindings, use the `buildtime_bindgen` Cargo feature.

## Author
Michael Lodder, redmike7@gmail.com

## Original Author

John Gallagher, johnkgallagher@gmail.com

## License

Rusqlcipher is available under the Apache Version 2 license. See the LICENSE file for more info.
Rusqlite is available under the MIT license. See the ORIGLICENSE file for more info.
