//! Country lookup from a MaxMind-format (`.mmdb`) country database.
//!
//! Works with MaxMind GeoLite2-Country and DB-IP Country Lite, which share
//! the same record layout. The database is optional: without one every
//! public address is reported as unknown.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use maxminddb::{Reader, geoip2};

/// A country as shown in the UI. Also used as the grouping key for the
/// per-country totals, hence the `Ord`/`Hash` derives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Country {
    /// ISO 3166-1 alpha-2 code (e.g. `CN`), `??` for unknown, `--` for
    /// private/local addresses.
    pub code: String,
    /// English country name.
    pub name: String,
}

impl Country {
    /// Build a `Country` from borrowed strings.
    fn new(code: &str, name: &str) -> Self {
        Self {
            code: code.to_string(),
            name: name.to_string(),
        }
    }
}

/// IP-to-country resolver.
pub struct Geo {
    /// The loaded database, read fully into memory; `None` if none was found.
    reader: Option<Reader<Vec<u8>>>,
    /// Path the database was loaded from, shown in the status line.
    pub source: Option<PathBuf>,
}

impl Geo {
    /// Open the database at `path`, or search the usual locations when `None`.
    /// A missing database is not an error: every lookup returns "unknown".
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(p) => Some(p.to_path_buf()),
            None => find_database(),
        };
        let reader = match &path {
            Some(p) => Some(
                Reader::open_readfile(p)
                    .with_context(|| format!("cannot open GeoIP database {}", p.display()))?,
            ),
            None => None,
        };
        Ok(Self {
            reader,
            source: path,
        })
    }

    /// Resolve `ip` to a country. Never fails: private addresses give `--`,
    /// and anything that cannot be resolved gives `??`.
    pub fn lookup(&self, ip: IpAddr) -> Country {
        // Private ranges are not in the databases; label them explicitly.
        if is_private(ip) {
            return Country::new("--", "Private/Local");
        }
        let unknown = Country::new("??", "Unknown");
        let Some(reader) = &self.reader else {
            return unknown;
        };
        let Ok(result) = reader.lookup(ip) else {
            return unknown;
        };
        // `Ok(None)` means the address is not in the database.
        let Ok(Some(rec)) = result.decode::<geoip2::Country>() else {
            return unknown;
        };
        match rec.country.iso_code {
            // Fall back to the code if the database has no English name.
            Some(code) => Country::new(code, rec.country.names.english.unwrap_or(code)),
            None => unknown,
        }
    }
}

/// True for addresses that never appear on the public internet: RFC 1918,
/// loopback and link-local (IPv4), and loopback, unique-local and link-local
/// (IPv6).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Directories searched for a database when `--geoip` is not given, in order.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/usr/share/GeoIP",
        "/var/lib/GeoIP",
        "/usr/local/share/GeoIP",
        "/etc/failedfrom",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/failedfrom"));
    }
    // Under sudo, HOME is usually root's; also look in the invoking user's home.
    if let Some(user) = std::env::var_os("SUDO_USER") {
        dirs.push(
            PathBuf::from("/home")
                .join(user)
                .join(".local/share/failedfrom"),
        );
    }
    dirs
}

/// First `.mmdb` file found, preferring files with "country" in the name.
fn find_database() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = search_dirs()
        .into_iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "mmdb"))
        .collect();
    // `false` sorts before `true`, so "country" files come first; the sort
    // is stable, so directory order is kept otherwise.
    candidates.sort_by_key(|p| {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        !name.contains("country")
    });
    candidates.into_iter().next()
}
