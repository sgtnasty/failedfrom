//! Rendering with ratatui.
//!
//! Screen layout:
//!
//! ```text
//! ┌ Countries ──────────┐┏ IPs — <country> ━━━━━━━━━━━━━━━━━━━━┓
//! │ * All countries ... │┃ IP  CC  Jails  Fails  Bans  ...     ┃
//! │ CN China ...        │┃ ...                                 ┃
//! └─────────────────────┘┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
//! key help
//! status message
//! ```
//!
//! The focused pane gets a thick cyan border. The unban confirmation is
//! drawn as a popup over everything else.

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::app::{App, Focus};

/// Draw one complete frame. `app` is mutable only so the table widgets can
/// update their scroll offsets in the `TableState`s.
pub fn draw(frame: &mut Frame, app: &mut App) {
    // Two panes on top, a two-line footer (key help + status) at the bottom.
    let [main, footer] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(2)]).areas(frame.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(main);

    draw_countries(frame, app, left);
    draw_ips(frame, app, right);
    draw_footer(frame, app, footer);

    // Drawn last so it sits on top of the panes.
    if app.confirm.is_some() {
        draw_confirm(frame, app);
    }
}

/// Bordered frame for a pane; the focused one stands out.
fn pane_block(title: String, focused: bool) -> Block<'static> {
    let block = Block::bordered().title(title);
    if focused {
        block
            .border_type(BorderType::Thick)
            .border_style(Style::new().fg(Color::Cyan))
    } else {
        block
    }
}

/// Style of the selected row: bright when the pane has focus, a plain
/// reverse-video bar otherwise so the selection stays visible.
fn highlight(focused: bool) -> Style {
    if focused {
        Style::new().bg(Color::Cyan).fg(Color::Black)
    } else {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}

/// Bold yellow column-title row.
fn header(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.iter().copied()).style(Style::new().bold().fg(Color::Yellow))
}

/// Left pane: one row per country plus the "All countries" total.
fn draw_countries(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Countries;
    let rows = app.countries.iter().map(|c| {
        let (code, name) = match &c.country {
            Some(c) => (c.code.clone(), c.name.clone()),
            None => ("*".into(), "All countries".into()),
        };
        let row = Row::new(vec![
            Cell::from(code),
            Cell::from(name),
            Cell::from(c.fails.to_string()),
            Cell::from(c.bans.to_string()),
            Cell::from(c.ips.to_string()),
            Cell::from(c.banned_now.to_string()),
        ]);
        // Make the total row stand out from the per-country rows.
        if c.country.is_none() { row.bold() } else { row }
    });
    // Fixed-width number columns; the country name takes the remaining space.
    let widths = [
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(header(&["CC", "Country", "Fails", "Bans", "IPs", "Banned"]))
        .block(pane_block(
            // Don't count the "All countries" row.
            format!(" Countries ({}) ", app.countries.len().saturating_sub(1)),
            focused,
        ))
        .row_highlight_style(highlight(focused));
    frame.render_stateful_widget(table, area, &mut app.country_state);
}

/// Right pane: the IPs of the selected country (or all of them), filtered
/// by the "banned only" toggle.
fn draw_ips(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Ips;
    let ips = app.visible_ips();
    let count = ips.len();
    let rows: Vec<Row> = ips
        .iter()
        .map(|r| {
            // Every jail the IP appeared in, banned or not.
            let jails = r.record.jails.keys().cloned().collect::<Vec<_>>().join(",");
            let banned = r.record.banned_jails();
            let status = if banned.is_empty() {
                Span::from("no").dim()
            } else {
                Span::from("BANNED").red().bold()
            };
            Row::new(vec![
                Cell::from(r.ip.to_string()),
                Cell::from(r.country.code.clone()),
                Cell::from(jails),
                Cell::from(r.record.fails.to_string()),
                Cell::from(r.record.bans.to_string()),
                Cell::from(r.record.last_seen.clone()),
                Cell::from(status),
            ])
        })
        .collect();
    // IP and jail columns flex; the rest are sized to their content (the
    // timestamp is always 19 characters).
    let widths = [
        Constraint::Min(15),
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(19),
        Constraint::Length(6),
    ];
    let scope = app
        .selected_country()
        .map_or("all countries".to_string(), |c| c.name.clone());
    let filter = if app.banned_only { ", banned only" } else { "" };
    let table = Table::new(rows, widths)
        .header(header(&[
            "IP",
            "CC",
            "Jails",
            "Fails",
            "Bans",
            "Last seen",
            "Status",
        ]))
        .block(pane_block(
            format!(" IPs — {scope}{filter} ({count}) "),
            focused,
        ))
        .row_highlight_style(highlight(focused));
    frame.render_stateful_widget(table, area, &mut app.ip_state);
}

/// Bottom two lines: key help (plus a dry-run marker) and the status message.
fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let key = |k: &'static str| Span::from(k).bold().fg(Color::Cyan);
    let keys = Line::from(vec![
        key("Tab"),
        " pane  ".into(),
        key("↑↓/jk"),
        " move  ".into(),
        key("u"),
        " unban  ".into(),
        key("b"),
        " banned only  ".into(),
        key("r"),
        " reload  ".into(),
        key("q"),
        " quit".into(),
        if app.config.dry_run {
            Span::from("   [DRY RUN]").yellow().bold()
        } else {
            "".into()
        },
    ]);
    let status = Line::from(app.status.as_str()).italic();
    frame.render_widget(Paragraph::new(vec![keys, status]), area);
}

/// Centered yes/no popup for the pending unban.
fn draw_confirm(frame: &mut Frame, app: &App) {
    let Some((ip, jails)) = &app.confirm else {
        return;
    };
    let area = centered(frame.area(), 60, 7);
    let text = vec![
        Line::from(vec!["Unban ".into(), Span::from(ip.to_string()).bold()]),
        Line::from(format!("from jail(s): {}", jails.join(", "))),
        Line::from(""),
        Line::from(vec![
            Span::from("y").bold().green(),
            " confirm   ".into(),
            Span::from("n/Esc").bold().red(),
            " cancel".into(),
        ]),
    ];
    // Blank the cells under the popup so the tables don't show through.
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: true }).block(
            Block::bordered()
                .title(" Confirm unban ")
                .border_type(BorderType::Rounded),
        ),
        area,
    );
}

/// A `width` x `height` rectangle in the middle of `area` (shrunk to fit if
/// `area` is smaller).
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}
