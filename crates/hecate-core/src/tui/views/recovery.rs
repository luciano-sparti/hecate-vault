use crate::tui::app::{FocusArea, TuiApp};
use crate::tui::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

pub fn render_recovery(f: &mut Frame, app: &TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Shamir Quorum Card
            Constraint::Length(7),  // DR Backup Trigger Card
            Constraint::Min(6),     // Recovery Procedures Guidelines
        ])
        .split(area);

    let border_style = if app.focus == FocusArea::MainContent {
        Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Theme::BORDER_NORMAL)
    };

    // 1. Shamir Custody Overview
    let quorum_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(" 🛡️ Shamir Secret Sharing Custody (M-of-N Quorum) ", Theme::subtitle()));

    let quorum_lines = vec![
        Line::from(vec![
            Span::styled("Master Key Split: ", Theme::muted()),
            Span::styled("3-of-5 Quorum (Shamir Polynomial over GF(2^8))", Theme::title()),
        ]),
        Line::from(vec![
            Span::styled("Root Sealing:     ", Theme::muted()),
            Span::styled(&state_guard.vault_db.root_provider, Theme::normal()),
            Span::styled(" (Hardware Enclave / TPM 2.0)", Theme::success()),
        ]),
        Line::from(vec![
            Span::styled("Custody Rule:     ", Theme::muted()),
            Span::styled("Any 3 shares required to reconstruct the Master Key on bare metal.", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Format Spec:      ", Theme::muted()),
            Span::styled("HCT-SHR-<threshold>-<total>-<index>-<hex_data>", Theme::subtitle()),
        ]),
    ];
    f.render_widget(Paragraph::new(quorum_lines).block(quorum_block), chunks[0]);

    // 2. DR Backup Card
    let backup_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 💾 Disaster Recovery Backup Archive ", Theme::subtitle()));

    let backup_lines = vec![
        Line::from(vec![
            Span::styled("Action: ", Theme::muted()),
            Span::styled("Press [b] to generate an encrypted DR snapshot (.hct bundle)", Theme::shortcut_key()),
        ]),
        Line::from(vec![
            Span::styled("Payload: ", Theme::muted()),
            Span::styled("Encrypted HSM Key Rings + Vault DB + Policies + Agent PKI + Audit Ledger", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Integrity: ", Theme::muted()),
            Span::styled("AES-256-GCM Envelope Sealed + Argon2id Passphrase KDF", Theme::success()),
        ]),
    ];
    f.render_widget(Paragraph::new(backup_lines).block(backup_block), chunks[1]);

    // 3. Operational Recovery Guidelines
    let guide_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 📖 Disaster Recovery Operating Procedures ", Theme::subtitle()));

    let guide_lines = vec![
        Line::from(vec![
            Span::styled("1. Bare-Metal Recovery: ", Theme::title()),
            Span::styled("Install hecate-core on new server and run `hecate-core backup restore`.", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("2. Custodian Ceremony:  ", Theme::title()),
            Span::styled("Gather 3 custodians with distinct physical share USB tokens / printouts.", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("3. Agent Continuity:    ", Theme::title()),
            Span::styled("Enrolled agents automatically resume mTLS heartbeats without re-enrollment.", Theme::normal()),
        ]),
    ];
    f.render_widget(Paragraph::new(guide_lines).block(guide_block), chunks[2]);
}
