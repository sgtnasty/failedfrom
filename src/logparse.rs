//! Parsing of fail2ban log files into per-IP records.
//!
//! Only four kinds of line matter:
//! - `Found <ip>`: the filter matched a failed attempt (counted as a "fail").
//! - `Ban <ip>` / `Restore Ban <ip>`: the IP was banned; `Restore Ban` is
//!   logged when fail2ban restarts and re-applies a ban that is still active.
//! - `Unban <ip>`: the ban was lifted (timed out or done by hand).
//!
//! Everything else in the log is ignored.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};
use flate2::read::MultiGzDecoder;
use regex::Regex;

/// Matches e.g.
///
/// Capture groups: 1 = timestamp without milliseconds, 2 = jail,
/// 3 = action word, 4 = address (validated later by parsing it as an IP).
/// `2026-10-29 09:00:49,789 fail2ban.actions [123]: NOTICE  [sshd] Ban 1.2.3.4`
/// `2026-10-29 09:00:41,001 fail2ban.filter  [123]: INFO    [sshd] Found 1.2.3.4 - 2026-10-29 09:00:41`
static LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.]\d+\s+fail2ban\.\S+\s+\[\d+\]:\s+\w+\s+\[([^\]]+)\]\s+(Restore Ban|Ban|Unban|Found)\s+(\S+)",
    )
    .expect("valid regex")
});

/// What a log line reports about an IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// A failed attempt matched by a jail's filter.
    Found,
    /// The IP was banned (including `Restore Ban` after a restart).
    Ban,
    /// The IP was unbanned.
    Unban,
}

/// One relevant log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `YYYY-MM-DD HH:MM:SS`; this format sorts correctly as plain text.
    pub timestamp: String,
    /// Jail name, e.g. `sshd`.
    pub jail: String,
    /// What happened.
    pub action: Action,
    /// The address the line is about.
    pub ip: IpAddr,
}

/// Parse a single log line; returns `None` for lines that are not
/// Found/Ban/Unban events.
pub fn parse_line(line: &str) -> Option<Event> {
    let caps = LINE_RE.captures(line)?;
    // Reject anything that is not a real address (e.g. a hostname).
    let ip: IpAddr = caps[4].parse().ok()?;
    let action = match &caps[3] {
        "Found" => Action::Found,
        "Unban" => Action::Unban,
        // "Ban" and "Restore Ban" both mean the IP is banned.
        _ => Action::Ban,
    };
    Some(Event {
        timestamp: caps[1].to_string(),
        jail: caps[2].to_string(),
        action,
        ip,
    })
}

/// Everything known about one IP after reading all the logs.
#[derive(Debug, Clone, Default)]
pub struct IpRecord {
    /// Number of `Found` events (failed attempts) across all jails.
    pub fails: u32,
    /// Number of bans across all jails.
    pub bans: u32,
    /// Timestamp of the most recent event of any kind.
    pub last_seen: String,
    /// Jail name -> currently banned in that jail.
    pub jails: BTreeMap<String, bool>,
}

impl IpRecord {
    /// Names of the jails the IP is banned in right now, in name order.
    pub fn banned_jails(&self) -> Vec<String> {
        self.jails
            .iter()
            .filter(|(_, banned)| **banned)
            .map(|(jail, _)| jail.clone())
            .collect()
    }

    /// True if the IP is banned in at least one jail.
    pub fn is_banned(&self) -> bool {
        self.jails.values().any(|b| *b)
    }
}

/// Fold events into per-IP records. Events are sorted by timestamp first so
/// the ban state reflects the most recent Ban/Unban regardless of file order.
pub fn aggregate(mut events: Vec<Event>) -> BTreeMap<IpAddr, IpRecord> {
    // Stable sort: events in the same second keep their order in the file.
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let mut records: BTreeMap<IpAddr, IpRecord> = BTreeMap::new();
    for ev in events {
        let rec = records.entry(ev.ip).or_default();
        // Every jail the IP shows up in is recorded, even for `Found` only,
        // so the UI can list where the attempts came in.
        let banned = rec.jails.entry(ev.jail).or_insert(false);
        match ev.action {
            Action::Found => rec.fails += 1,
            Action::Ban => {
                rec.bans += 1;
                *banned = true;
            }
            Action::Unban => *banned = false,
        }
        rec.last_seen = ev.timestamp;
    }
    records
}

/// Default log set: `/var/log/fail2ban.log` and its rotations (`.1`, `.2.gz`, ...).
pub fn default_logs() -> Vec<PathBuf> {
    // A missing or unreadable /var/log just yields an empty list here;
    // `check_readable` in main.rs reports the real problem.
    let mut logs: Vec<PathBuf> = std::fs::read_dir("/var/log")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("fail2ban.log"))
        })
        .collect();
    logs.sort();
    // Nothing found: fall back to the usual path so the error message names it.
    if logs.is_empty() {
        logs.push(PathBuf::from("/var/log/fail2ban.log"));
    }
    logs
}

/// Open a log file for line-by-line reading, decompressing `.gz` files.
/// `MultiGzDecoder` also handles files made of several gzip members.
fn open_log(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let reader: Box<dyn Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::new(reader)))
}

/// Read and parse all given log files, returning the relevant events in file
/// order. Fails on the first file that cannot be opened or read.
pub fn read_logs(paths: &[PathBuf]) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for path in paths {
        let mut reader = open_log(path)?;
        let mut buf = Vec::new();
        // Read raw bytes so a stray non-UTF-8 line does not abort the scan.
        while reader.read_until(b'\n', &mut buf)? > 0 {
            if let Some(ev) = parse_line(&String::from_utf8_lossy(&buf)) {
                events.push(ev);
            }
            buf.clear();
        }
    }
    Ok(events)
}

/// Parser and aggregation tests using sample log lines.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ban() {
        let ev = parse_line(
            "2026-10-29 09:00:49,789 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 203.0.113.7",
        )
        .unwrap();
        assert_eq!(ev.action, Action::Ban);
        assert_eq!(ev.jail, "sshd");
        assert_eq!(ev.ip.to_string(), "203.0.113.7");
        assert_eq!(ev.timestamp, "2026-10-29 09:00:49");
    }

    #[test]
    fn parses_restore_ban_as_ban() {
        let ev = parse_line(
            "2026-10-29 09:00:49,789 fail2ban.actions        [1234]: NOTICE  [nginx-http-auth] Restore Ban 198.51.100.2",
        )
        .unwrap();
        assert_eq!(ev.action, Action::Ban);
        assert_eq!(ev.jail, "nginx-http-auth");
    }

    #[test]
    fn parses_found_and_ipv6() {
        let ev = parse_line(
            "2026-10-29 09:00:41,001 fail2ban.filter         [1234]: INFO    [sshd] Found 2001:db8::1 - 2026-10-29 09:00:41",
        )
        .unwrap();
        assert_eq!(ev.action, Action::Found);
        assert_eq!(ev.ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn parses_unban() {
        let ev = parse_line(
            "2026-10-29 10:00:49,789 fail2ban.actions        [1234]: NOTICE  [sshd] Unban 203.0.113.7",
        )
        .unwrap();
        assert_eq!(ev.action, Action::Unban);
    }

    #[test]
    /// Lines that mention an IP but are not Found/Ban/Unban events, plus
    /// a Ban line with an invalid address, must all be skipped.
    fn ignores_other_lines() {
        for line in [
            "2026-10-29 09:00:50,100 fail2ban.actions        [1234]: NOTICE  [sshd] 203.0.113.7 already banned",
            "2026-10-29 09:00:50,100 fail2ban.actions        [1234]: NOTICE  [sshd] Increase Ban 203.0.113.7 (2 # 2:00:00 -> 2026-10-29 11:00:50)",
            "2026-10-29 09:00:50,100 fail2ban.server         [1234]: INFO    Starting Fail2ban v1.1.0",
            "2026-10-29 09:00:50,100 fail2ban.actions        [1234]: NOTICE  [sshd] Ban not-an-ip",
        ] {
            assert!(parse_line(line).is_none(), "{line}");
        }
    }

    #[test]
    /// The Unban line is listed first but is the newest event, so after
    /// sorting the sshd ban is lifted while the recidive ban stays.
    fn aggregate_tracks_ban_state_per_jail() {
        let lines = [
            "2026-10-29 10:00:00,000 fail2ban.actions [1]: NOTICE  [sshd] Unban 203.0.113.7",
            "2026-10-29 09:00:00,000 fail2ban.filter  [1]: INFO    [sshd] Found 203.0.113.7 - x",
            "2026-10-29 09:00:01,000 fail2ban.filter  [1]: INFO    [sshd] Found 203.0.113.7 - x",
            "2026-10-29 09:00:02,000 fail2ban.actions [1]: NOTICE  [sshd] Ban 203.0.113.7",
            "2026-10-29 09:30:00,000 fail2ban.actions [1]: NOTICE  [recidive] Ban 203.0.113.7",
        ];
        let records = aggregate(lines.iter().filter_map(|l| parse_line(l)).collect());
        let rec = &records[&"203.0.113.7".parse::<IpAddr>().unwrap()];
        assert_eq!(rec.fails, 2);
        assert_eq!(rec.bans, 2);
        assert_eq!(rec.banned_jails(), vec!["recidive".to_string()]);
        assert_eq!(rec.last_seen, "2026-10-29 10:00:00");
    }
}
