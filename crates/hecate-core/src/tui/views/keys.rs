use crate::tui::app::{FocusArea, TuiApp};
use crate::tui::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

pub fn render_keys(f: &mut Frame, app: &mut TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55), // Keys Table
            Constraint::Percentage(45), // Key Details & Versions
        ])
        .split(area);

    let keys = state_guard.hsm.list_keys();
    let selected_idx = app.keys_table_state.selected().unwrap_or(0);

    // 1. Interactive Table of HSM Keys
    let rows: Vec<Row> = keys
        .iter()
        .enumerate()
        .map(|(idx, meta)| {
            let is_selected = idx == selected_idx;
            let key_type_str = match meta.key_type {
                hecate_crypto::KeyType::Aes256Gcm => "AES-256-GCM",
                hecate_crypto::KeyType::ChaCha20Poly1305 => "ChaCha20-Poly1305",
                hecate_crypto::KeyType::HmacSha256 => "HMAC-SHA256",
            };

            let state_span = match meta.state {
                hecate_crypto::KeyState::Active => Span::styled("ACTIVE 🟢", Theme::success()),
                hecate_crypto::KeyState::PreActive => Span::styled("PRE-ACTIVE 🟡", Theme::warning()),
                hecate_crypto::KeyState::Deactivated => Span::styled("DEACTIVATED 🟡", Theme::warning()),
                hecate_crypto::KeyState::Compromised => Span::styled("COMPROMISED 🔴", Theme::danger()),
                hecate_crypto::KeyState::Destroyed => Span::styled("DESTROYED 💀", Theme::danger()),
            };

            let row_style = if is_selected {
                Theme::selected_row()
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(Span::styled(&meta.key_id, Theme::normal())),
                Cell::from(Span::styled(&meta.key_alias, Theme::title())),
                Cell::from(Span::styled(key_type_str, Theme::normal())),
                Cell::from(Span::styled(format!("v{}", meta.current_version), Theme::subtitle())),
                Cell::from(state_span),
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
            Constraint::Length(22),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Length(10),
            Constraint::Length(18),
        ],
    )
    .header(
        Row::new(vec!["KEY ID", "KEY ALIAS", "ALGORITHM", "VERSION", "STATE"])
            .style(Theme::table_header()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title(Span::styled(" 🔑 HSM Managed Keys ([n] Create Key | [r] Rotate Version | [↑/↓] Select) ", Theme::subtitle())),
    )
    .row_highlight_style(Theme::selected_row());

    f.render_stateful_widget(table, chunks[0], &mut app.keys_table_state);

    // 2. Selected Key Metadata & Version Breakdown
    let detail_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    if let Some(meta) = keys.get(selected_idx) {
        // Left: Cryptographic Parameters
        let param_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(format!(" 📋 Key Profile: {} ", meta.key_alias), Theme::subtitle()));

        let param_lines = vec![
            Line::from(vec![
                Span::styled("Key ID: ", Theme::muted()),
                Span::styled(&meta.key_id, Theme::title()),
            ]),
            Line::from(vec![
                Span::styled("Key Alias: ", Theme::muted()),
                Span::styled(&meta.key_alias, Theme::normal()),
            ]),
            Line::from(vec![
                Span::styled("Algorithm: ", Theme::muted()),
                Span::styled(format!("{:?}", meta.key_type), Theme::normal()),
            ]),
            Line::from(vec![
                Span::styled("Memory Protection: ", Theme::muted()),
                Span::styled("mlock (Page Locked) + ZeroizeOnDrop", Theme::success()),
            ]),
            Line::from(vec![
                Span::styled("Envelope Role: ", Theme::muted()),
                Span::styled("Tier-2 Key Encryption Key (KEK)", Theme::normal()),
            ]),
        ];
        f.render_widget(Paragraph::new(param_lines).block(param_block), detail_chunks[0]);

        // Right: Version History & Usage
        let ver_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(" 🔄 Version History & Rotation ", Theme::subtitle()));

        let mut ver_lines = Vec::new();
        for v in (1..=meta.current_version).rev() {
            let is_current = v == meta.current_version;
            let status = if is_current {
                Span::styled(" [CURRENT ACTIVE 🟢]", Theme::success())
            } else {
                Span::styled(" [HISTORICAL / DECRYPT-ONLY 🟡]", Theme::muted())
            };

            ver_lines.push(Line::from(vec![
                Span::styled(format!("• Version {}: ", v), Theme::title()),
                Span::styled("256-bit Key Material Sealed", Theme::normal()),
                status,
            ]));
        }

        f.render_widget(Paragraph::new(ver_lines).block(ver_block), detail_chunks[1]);
    } else {
        let empty_p = Paragraph::new("No keys created yet. Press [n] to create a new HSM key.")
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
            .style(Theme::muted());
        f.render_widget(empty_p, chunks[1]);
    }
}
