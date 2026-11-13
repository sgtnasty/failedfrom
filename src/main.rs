//! failedfrom: a terminal UI for fail2ban.
//!
//! Reads the fail2ban log files, groups failed attempts and bans by IP
//! address and by country, and lets the user unban an IP through
//! `fail2ban-client`.
//!
//! Module overview:
//! - [`logparse`]: turns log lines into events and per-IP records.
//! - [`geo`]: maps IP addresses to countries using an `.mmdb` database.
//! - [`app`]: application state, aggregation per country, and unbanning.
//! - [`ui`]: draws the state with ratatui.
//!
//! This file holds the command line, start-up checks, the key-handling
//! event loop, and the non-interactive `--dump` and `--json` output.

mod app;
mod geo;
mod logparse;
mod ui;

use std::io::{ErrorKind, Write};
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use serde::Serialize;

use app::{App, Config};
use geo::Geo;

/// Monitor fail2ban bans by IP and country, and unban selected IPs.
#[derive(Parser)]
#[command(version)]
struct Cli {
    // The `///` comments on these fields double as the `--help` text.
    /// fail2ban log file(s) to read; may be repeated. `.gz` files are
    /// decompressed. Default: /var/log/fail2ban.log*
    #[arg(short, long = "log", value_name = "PATH")]
    logs: Vec<PathBuf>,

    /// Country database in MaxMind .mmdb format (GeoLite2-Country or
    /// DB-IP Country Lite). Searched for in common locations if omitted.
    #[arg(short, long, value_name = "PATH")]
    geoip: Option<PathBuf>,

    /// fail2ban client binary used for unbanning.
    #[arg(long, default_value = "fail2ban-client", value_name = "PATH")]
    client: String,

    /// Show the unban command instead of running it.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Print the country and IP tables to stdout instead of starting the UI.
    #[arg(short, long, conflicts_with = "json")]
    dump: bool,

    /// Print all data (totals, countries, and every IP with its per-jail
    /// ban state) as JSON to stdout instead of starting the UI.
    #[arg(short, long)]
    json: bool,
}

/// Entry point: parse arguments, load the data, then either print it
/// (`--dump`) or run the interactive UI.
fn main() -> Result<()> {
    let cli = Cli::parse();
    let logs = if cli.logs.is_empty() {
        logparse::default_logs()
    } else {
        cli.logs
    };
    // Check permissions now so the user gets a plain error message instead of
    // a failure after the terminal has been switched to the TUI.
    check_readable(&logs)?;

    let geo = Geo::open(cli.geoip.as_deref())?;
    let config = Config {
        logs,
        client: cli.client,
        dry_run: cli.dry_run,
    };
    let mut app = App::new(config, geo)?;

    if cli.dump {
        dump(&app);
        return Ok(());
    }
    if cli.json {
        dump_json(&app)?;
        return Ok(());
    }

    // `init` enters raw mode and the alternate screen, and installs a panic
    // hook that restores the terminal; `restore` undoes it on normal exit.
    let terminal = ratatui::init();
    let result = run(terminal, &mut app);
    ratatui::restore();
    result
}

/// Fail early, before entering the TUI, when the logs cannot be read.
fn check_readable(logs: &[PathBuf]) -> Result<()> {
    for path in logs {
        if let Err(e) = std::fs::File::open(path) {
            if e.kind() == ErrorKind::PermissionDenied {
                bail!(
                    "permission denied reading {} — run with sudo (fail2ban logs and socket are root-only)",
                    path.display()
                );
            }
            bail!("cannot read {}: {e}", path.display());
        }
    }
    Ok(())
}

/// The event loop: redraw, wait for a key, update the state; repeat until
/// the user quits.
fn run(mut terminal: DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.quit {
        terminal.draw(|f| ui::draw(f, app))?;
        // Block until the next terminal event; resizes and mouse events
        // simply cause a redraw on the next iteration.
        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Some terminals also report key release/repeat; act on presses only.
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break;
        }
        // While the unban popup is open it captures all keys.
        if app.confirm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_unban(),
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {
                    app.confirm = None;
                    app.status = "Unban cancelled".into();
                }
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => app.toggle_focus(),
            KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
            KeyCode::PageDown => app.move_selection(10),
            KeyCode::PageUp => app.move_selection(-10),
            // Home/End use huge deltas that `move_selection` clamps to the
            // first/last row (halved so the addition cannot overflow).
            KeyCode::Home | KeyCode::Char('g') => app.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => app.move_selection(isize::MAX / 2),
            KeyCode::Char('u') => app.request_unban(),
            KeyCode::Char('b') => app.toggle_banned_only(),
            KeyCode::Char('r') => match app.reload() {
                Ok(()) => app.status = format!("Reloaded {} IPs", app.rows.len()),
                Err(e) => app.status = format!("Reload failed: {e:#}"),
            },
            _ => {}
        }
    }
    Ok(())
}

/// Print the country table and the full IP table as plain text, for use in
/// scripts or for checking the parser without the TUI.
fn dump(app: &App) {
    // Country table: same columns as the left pane.
    println!(
        "{:<3} {:<28} {:>6} {:>5} {:>5} {:>6}",
        "CC", "Country", "Fails", "Bans", "IPs", "Banned"
    );
    for c in &app.countries {
        let (code, name) = c.country.as_ref().map_or(("*", "All countries"), |c| {
            (c.code.as_str(), c.name.as_str())
        });
        println!(
            "{code:<3} {name:<28} {:>6} {:>5} {:>5} {:>6}",
            c.fails, c.bans, c.ips, c.banned_now
        );
    }
    println!();
    // IP table: every IP, not filtered by country. 39 columns fits the
    // longest IPv6 address.
    println!(
        "{:<39} {:<3} {:>6} {:>5} {:<19} Banned in",
        "IP", "CC", "Fails", "Bans", "Last seen"
    );
    for r in &app.rows {
        println!(
            "{:<39} {:<3} {:>6} {:>5} {:<19} {}",
            r.ip.to_string(),
            r.country.code,
            r.record.fails,
            r.record.bans,
            r.record.last_seen,
            r.record.banned_jails().join(",")
        );
    }
}

/// Top-level `--json` document.
#[derive(Serialize)]
struct JsonDump<'a> {
    /// Path of the GeoIP database used, or `null` if none was found.
    geoip: Option<String>,
    /// Log files that were read.
    logs: Vec<String>,
    /// Totals over every IP (the "All countries" row).
    totals: JsonCounts,
    /// Per-country totals, sorted like the country pane.
    countries: Vec<JsonCountry<'a>>,
    /// Every IP, sorted like the IP pane.
    ips: Vec<JsonIp<'a>>,
}

#[derive(Serialize)]
struct JsonCounts {
    fails: u32,
    bans: u32,
    ips: u32,
    banned_now: u32,
}

#[derive(Serialize)]
struct JsonCountry<'a> {
    code: &'a str,
    name: &'a str,
    #[serde(flatten)]
    counts: JsonCounts,
}

#[derive(Serialize)]
struct JsonIp<'a> {
    ip: String,
    country_code: &'a str,
    country_name: &'a str,
    fails: u32,
    bans: u32,
    last_seen: &'a str,
    banned: bool,
    /// Jail name -> currently banned in that jail.
    jails: &'a std::collections::BTreeMap<String, bool>,
}

/// Print everything the UI knows as a single pretty-printed JSON document.
fn dump_json(app: &App) -> Result<()> {
    let counts = |c: &app::CountryRow| JsonCounts {
        fails: c.fails,
        bans: c.bans,
        ips: c.ips,
        banned_now: c.banned_now,
    };
    let doc = JsonDump {
        geoip: app.geo.source.as_ref().map(|p| p.display().to_string()),
        logs: app
            .config
            .logs
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        // Index 0 is always the "All countries" row.
        totals: counts(&app.countries[0]),
        countries: app
            .countries
            .iter()
            .filter_map(|c| {
                c.country.as_ref().map(|country| JsonCountry {
                    code: &country.code,
                    name: &country.name,
                    counts: counts(c),
                })
            })
            .collect(),
        ips: app
            .rows
            .iter()
            .map(|r| JsonIp {
                ip: r.ip.to_string(),
                country_code: &r.country.code,
                country_name: &r.country.name,
                fails: r.record.fails,
                bans: r.record.bans,
                last_seen: &r.record.last_seen,
                banned: r.record.is_banned(),
                jails: &r.record.jails,
            })
            .collect(),
    };
    let mut out = std::io::stdout().lock();
    let written = serde_json::to_writer_pretty(&mut out, &doc)
        .map_err(std::io::Error::from)
        .and_then(|()| writeln!(out));
    match written {
        // The reader went away (e.g. piped into `head`): not an error.
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        r => Ok(r?),
    }
}
