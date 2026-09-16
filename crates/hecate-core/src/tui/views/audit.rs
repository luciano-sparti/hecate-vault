use crate::tui::app::{FocusArea, TuiApp};
use crate::tui::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

pub fn render_audit(f: &mut Frame, app: &mut TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),      // Hash Chain Banner
            Constraint::Percentage(55), // Audit Log Table
            Constraint::Percentage(40), // Entry Payload Inspector
        ])
        .split(area);

    // 1. Hash Chain Integrity Banner
    let banner_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if app.audit_verified {
            Style::default().fg(Theme::SUCCESS)
        } else {
            Style::default().fg(Theme::DANGER)
        })
        .title(Span::styled(" 🔒 Cryptographic Hash Chain Verification ", Theme::subtitle()));

    let total_entries = state_guard.audit_ledger.entries().len();
    let banner_text = if app.audit_verified {
        vec![Line::from(vec![
            Span::styled("CHAIN STATUS: ", Theme::muted()),
            Span::styled("VALID & UNBROKEN ✓", Theme::success()),
            Span::styled(format!(" ({} Tamper-Evident SHA-256 Ledger Entries) ", total_entries), Theme::normal()),
            Span::styled(" [Press 'v' to Re-Verify Chain]", Theme::shortcut_key()),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled("CHAIN STATUS: ", Theme::muted()),
            Span::styled("CORRUPTED / TAMPER DETECTED ✗", Theme::danger()),
            Span::styled(" [Alert: Hash Mismatch Detected!]", Theme::danger()),
        ])]
    };
    f.render_widget(Paragraph::new(banner_text).block(banner_block), chunks[0]);

    // 2. Audit Table
    let entries = state_guard.audit_ledger.entries();
    let selected_idx = app.audit_table_state.selected().unwrap_or(0);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let is_selected = idx == selected_idx;
            let action_style = match entry.action.as_str() {
                a if a.contains("ROTATE") || a.contains("CREATE") || a.contains("GEN") => Theme::warning(),
                a if a.contains("ENROLL") || a.contains("INIT") => Theme::success(),
                a if a.contains("DESTROY") || a.contains("REVOKE") => Theme::danger(),
                _ => Theme::normal(),
            };

            let row_style = if is_selected {
                Theme::selected_row()
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(Span::styled(format!("#{}", entry.index), Theme::muted())),
                Cell::from(Span::styled(&entry.timestamp[..19], Theme::normal())),
                Cell::from(Span::styled(&entry.actor, Theme::normal())),
                Cell::from(Span::styled(&entry.action, action_style)),
                Cell::from(Span::styled(&entry.details, Theme::normal())),
                Cell::from(Span::styled(
                    if entry.entry_hash.len() >= 16 { &entry.entry_hash[..16] } else { &entry.entry_hash },
                    Theme::subtitle(),
                )),
            ])
            .style(row_style)
        })
        .collect();

    let border_style = if app.focus == FocusArea::MainContent {
        Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Theme::BORDER_NORMAL)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(22),
            Constraint::Length(16),
            Constraint::Length(18),
            Constraint::Percentage(40),
            Constraint::Length(18),
        ],
    )
    .header(
        Row::new(vec!["#", "TIMESTAMP (UTC)", "ACTOR", "ACTION", "DETAILS", "SHA-256 HASH"])
            .style(Theme::table_header()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title(Span::styled(" 📜 Audit Ledger Events ([↑/↓] Select | [Enter] Inspect JSON) ", Theme::subtitle())),
    )
    .row_highlight_style(Theme::selected_row());

    f.render_stateful_widget(table, chunks[1], &mut app.audit_table_state);

    // 3. Selected Entry Inspector
    if let Some(entry) = entries.get(selected_idx) {
        let inspect_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(format!(" 🔍 Entry Inspector: Event #{} ", entry.index), Theme::subtitle()));

        let inspect_lines = vec![
            Line::from(vec![
                Span::styled("Entry Hash: ", Theme::muted()),
                Span::styled(&entry.entry_hash, Theme::title()),
            ]),
            Line::from(vec![
                Span::styled("Prev Hash:  ", Theme::muted()),
                Span::styled(&entry.prev_hash, Theme::subtitle()),
            ]),
            Line::from(vec![
                Span::styled("Timestamp:  ", Theme::muted()),
                Span::styled(&entry.timestamp, Theme::normal()),
                Span::styled("  | Actor: ", Theme::muted()),
                Span::styled(&entry.actor, Theme::normal()),
                Span::styled("  | Action: ", Theme::muted()),
                Span::styled(&entry.action, Theme::warning()),
            ]),
            Line::from(vec![
                Span::styled("Details:    ", Theme::muted()),
                Span::styled(&entry.details, Theme::normal()),
            ]),
            Line::from(vec![
                Span::styled("Chain Proof: SHA-256(index || time || action || actor || details || prev_hash) = MATCH ✓", Theme::success()),
            ]),
        ];

        f.render_widget(Paragraph::new(inspect_lines).block(inspect_block), chunks[2]);
    }
}
