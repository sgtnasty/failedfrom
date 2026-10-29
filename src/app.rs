//! Application state: per-IP rows, per-country aggregates, selection and unban.
//!
//! [`App`] owns everything the UI renders. It is built once from the parsed
//! logs, rebuilt on reload, and mutated by the key handlers in `main.rs`.
//! Rendering itself lives in `ui.rs` and only reads from this state (apart
//! from the ratatui [`TableState`]s, which the table widgets update).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use ratatui::widgets::TableState;

use crate::geo::{Country, Geo};
use crate::logparse::{self, IpRecord};

/// One IP address as shown in the IP pane.
pub struct IpRow {
    /// The offending address (IPv4 or IPv6).
    pub ip: IpAddr,
    /// Country the address resolves to (or the "unknown"/"private" markers).
    pub country: Country,
    /// Counters and per-jail ban state collected from the logs.
    pub record: IpRecord,
}

/// One line of the country pane: totals over every IP from that country.
#[derive(Default)]
pub struct CountryRow {
    /// The country, or `None` for the synthetic "All countries" row.
    pub country: Option<Country>,
    /// Sum of `Found` (failed attempt) events.
    pub fails: u32,
    /// Sum of `Ban` / `Restore Ban` events.
    pub bans: u32,
    /// Number of distinct IP addresses.
    pub ips: u32,
    /// Number of those IPs that are banned in at least one jail right now.
    pub banned_now: u32,
}

impl CountryRow {
    /// Fold a single IP's counters into this country's totals.
    fn add(&mut self, row: &IpRow) {
        self.fails += row.record.fails;
        self.bans += row.record.bans;
        self.ips += 1;
        if row.record.is_banned() {
            self.banned_now += 1;
        }
    }
}

/// Which pane receives the movement keys.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// The country list on the left.
    Countries,
    /// The IP list on the right.
    Ips,
}

/// Settings taken from the command line.
pub struct Config {
    /// Log files to parse (plain or `.gz`).
    pub logs: Vec<PathBuf>,
    /// Program run to unban, normally `fail2ban-client`.
    pub client: String,
    /// When set, unbanning only reports the command it would run.
    pub dry_run: bool,
}

/// The whole application state.
pub struct App {
    /// Command-line settings.
    pub config: Config,
    /// Country lookup for IP addresses.
    pub geo: Geo,
    /// Every IP seen in the logs, sorted by fails then bans (descending).
    pub rows: Vec<IpRow>,
    /// Country aggregates; index 0 is always the "All countries" row.
    pub countries: Vec<CountryRow>,
    /// Selection and scroll offset of the country table.
    pub country_state: TableState,
    /// Selection and scroll offset of the IP table (indexes `visible_ips()`).
    pub ip_state: TableState,
    /// Pane that currently has keyboard focus.
    pub focus: Focus,
    /// Hide IPs that are not currently banned.
    pub banned_only: bool,
    /// Pending unban confirmation: (ip, jails).
    pub confirm: Option<(IpAddr, Vec<String>)>,
    /// Message shown on the bottom line of the footer.
    pub status: String,
    /// Set to leave the event loop.
    pub quit: bool,
}

impl App {
    /// Build the state and load the logs for the first time.
    ///
    /// Fails if a log file cannot be read or parsed.
    pub fn new(config: Config, geo: Geo) -> Result<Self> {
        let mut app = Self {
            config,
            geo,
            rows: Vec::new(),
            countries: Vec::new(),
            country_state: TableState::default().with_selected(0),
            ip_state: TableState::default().with_selected(0),
            focus: Focus::Countries,
            banned_only: false,
            confirm: None,
            status: String::new(),
            quit: false,
        };
        app.reload()?;
        // Tell the user up front where countries come from, or why they are
        // all "??".
        app.status = match &app.geo.source {
            Some(p) => format!("GeoIP: {}", p.display()),
            None => "No GeoIP database found; countries shown as ?? (see --geoip)".into(),
        };
        Ok(app)
    }

    /// Re-read the logs, keeping the selected country where possible.
    pub fn reload(&mut self) -> Result<()> {
        // Remember the country by value: its index may change after re-sorting.
        let selected = self.selected_country().cloned();
        let events = logparse::read_logs(&self.config.logs)?;
        self.rows = logparse::aggregate(events)
            .into_iter()
            .map(|(ip, record)| IpRow {
                ip,
                country: self.geo.lookup(ip),
                record,
            })
            .collect();
        // Most fails first, then most bans; ties broken by ascending IP.
        self.rows.sort_by(|a, b| {
            (b.record.fails, b.record.bans, a.ip).cmp(&(a.record.fails, a.record.bans, b.ip))
        });
        self.rebuild_countries();
        // Re-select the same country, falling back to "All countries" if it
        // no longer appears in the logs.
        let idx = selected
            .and_then(|c| {
                self.countries
                    .iter()
                    .position(|r| r.country.as_ref() == Some(&c))
            })
            .unwrap_or(0);
        self.country_state.select(Some(idx));
        self.clamp_ip_selection();
        Ok(())
    }

    /// Recompute `countries` from `rows`.
    ///
    /// Called after a reload and after an unban (which changes `banned_now`).
    /// The sort key does not involve ban state, so an unban never reorders
    /// the list and the current selection stays on the same country.
    fn rebuild_countries(&mut self) {
        let mut all = CountryRow::default();
        let mut by_country: BTreeMap<Country, CountryRow> = BTreeMap::new();
        for row in &self.rows {
            all.add(row);
            by_country
                .entry(row.country.clone())
                .or_insert_with(|| CountryRow {
                    country: Some(row.country.clone()),
                    ..Default::default()
                })
                .add(row);
        }
        let mut list: Vec<CountryRow> = by_country.into_values().collect();
        list.sort_by_key(|c| std::cmp::Reverse((c.fails, c.bans, c.ips)));
        // "All countries" is pinned to the top, above the sorted list.
        self.countries = std::iter::once(all).chain(list).collect();
    }

    /// The country selected in the left pane, or `None` for "All countries".
    pub fn selected_country(&self) -> Option<&Country> {
        self.country_state
            .selected()
            .and_then(|i| self.countries.get(i))
            .and_then(|r| r.country.as_ref())
    }

    /// Rows shown in the IP pane for the current country/filter.
    pub fn visible_ips(&self) -> Vec<&IpRow> {
        let country = self.selected_country();
        self.rows
            .iter()
            .filter(|r| country.is_none_or(|c| &r.country == c))
            .filter(|r| !self.banned_only || r.record.is_banned())
            .collect()
    }

    /// Keep the IP selection inside the visible list after it shrinks or grows.
    fn clamp_ip_selection(&mut self) {
        let len = self.visible_ips().len();
        let sel = self.ip_state.selected().unwrap_or(0);
        self.ip_state.select(if len == 0 {
            None
        } else {
            Some(sel.min(len - 1))
        });
    }

    /// Move the selection in the focused pane by `delta` rows (negative is up).
    /// Large deltas are used for Home/End and are clamped to the list bounds.
    pub fn move_selection(&mut self, delta: isize) {
        match self.focus {
            Focus::Countries => {
                let len = self.countries.len();
                step(&mut self.country_state, len, delta);
                // A new country means a new IP list: start at its top.
                self.ip_state.select(Some(0));
                self.clamp_ip_selection();
            }
            Focus::Ips => {
                let len = self.visible_ips().len();
                step(&mut self.ip_state, len, delta);
            }
        }
    }

    /// Switch keyboard focus to the other pane.
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Countries => Focus::Ips,
            Focus::Ips => Focus::Countries,
        };
    }

    /// Toggle the "banned only" filter on the IP pane.
    pub fn toggle_banned_only(&mut self) {
        self.banned_only = !self.banned_only;
        self.clamp_ip_selection();
    }

    /// Open the confirmation popup for the selected IP if it is banned.
    pub fn request_unban(&mut self) {
        // (ip, jails it is currently banned in) for the highlighted row.
        let Some(row) = self.ip_state.selected().and_then(|i| {
            self.visible_ips()
                .get(i)
                .map(|r| (r.ip, r.record.banned_jails()))
        }) else {
            self.status = "No IP selected".into();
            return;
        };
        if row.1.is_empty() {
            self.status = format!("{} is not currently banned", row.0);
        } else {
            self.confirm = Some(row);
        }
    }

    /// Carry out the pending unban: run the client once per jail, report the
    /// outcome in the status line, and mark the successful jails unbanned.
    pub fn confirm_unban(&mut self) {
        let Some((ip, jails)) = self.confirm.take() else {
            return;
        };
        let mut msgs = Vec::new();
        let mut ok_jails = Vec::new();
        for jail in &jails {
            // Arguments go straight to the program (no shell), so jail names
            // and addresses cannot be interpreted as shell syntax.
            let args = ["set", jail.as_str(), "unbanip", &ip.to_string()];
            if self.config.dry_run {
                msgs.push(format!(
                    "[dry-run] {} {}",
                    self.config.client,
                    args.join(" ")
                ));
                ok_jails.push(jail.clone());
                continue;
            }
            match Command::new(&self.config.client).args(args).output() {
                Ok(out) if out.status.success() => {
                    msgs.push(format!("unbanned {ip} from {jail}"));
                    ok_jails.push(jail.clone());
                }
                Ok(out) => {
                    // fail2ban-client reports some errors on stdout, so fall
                    // back to it when stderr is empty.
                    let err = String::from_utf8_lossy(&out.stderr);
                    let err = err.trim();
                    let err = if err.is_empty() {
                        String::from_utf8_lossy(&out.stdout).trim().to_string()
                    } else {
                        err.to_string()
                    };
                    msgs.push(format!("{jail}: failed ({}) {err}", out.status));
                }
                Err(e) => msgs.push(format!("{jail}: cannot run {}: {e}", self.config.client)),
            }
        }
        // fail2ban logs the Unban itself; mark it locally so the UI updates now.
        if let Some(row) = self.rows.iter_mut().find(|r| r.ip == ip) {
            for jail in &ok_jails {
                row.record.jails.insert(jail.clone(), false);
            }
        }
        self.rebuild_countries();
        // The row may have disappeared if the "banned only" filter is on.
        self.clamp_ip_selection();
        self.status = msgs.join("; ");
    }
}

/// Move a table selection by `delta`, clamped to `0..len`; clears the
/// selection when the table is empty.
fn step(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as isize;
    state.select(Some((cur + delta).clamp(0, len as isize - 1) as usize));
}
