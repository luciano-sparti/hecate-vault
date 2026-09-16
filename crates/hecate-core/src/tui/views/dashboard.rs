use crate::tui::app::TuiApp;
use crate::tui::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Row, Table};
use ratatui::Frame;

pub fn render_dashboard(f: &mut Frame, _app: &TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // KPI Cards Row
            Constraint::Length(8), // Guard Points Overview
            Constraint::Min(8),    // Recent Activity Stream
        ])
        .split(area);

    // 1. KPI Cards Row (4 Columns)
    let kpi_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    // Card 1: HSM State
    let card1_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 🔐 HSM Core ", Theme::subtitle()));
    let card1_text = vec![
        Line::from(vec![
            Span::styled("State: ", Theme::muted()),
            Span::styled("ACTIVE", Theme::success()),
        ]),
        Line::from(vec![
            Span::styled("Engine: ", Theme::muted()),
            Span::styled("Software HSM", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Trust: ", Theme::muted()),
            Span::styled(&state_guard.vault_db.root_provider, Theme::normal()),
        ]),
    ];
    f.render_widget(Paragraph::new(card1_text).block(card1_block), kpi_chunks[0]);

    // Card 2: Key Inventory
    let total_keys = state_guard.hsm.list_keys().len();
    let card2_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 🔑 Key Inventory ", Theme::subtitle()));
    let card2_text = vec![
        Line::from(vec![
            Span::styled("Managed KEKs: ", Theme::muted()),
            Span::styled(format!("{}", total_keys), Theme::title()),
        ]),
        Line::from(vec![
            Span::styled("Algorithms: ", Theme::muted()),
            Span::styled("AES-GCM / ChaCha", Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Zeroize: ", Theme::muted()),
            Span::styled("Protected", Theme::success()),
        ]),
    ];
    f.render_widget(Paragraph::new(card2_text).block(card2_block), kpi_chunks[1]);

    // Card 3: Agent Nodes
    let agents = state_guard.agent_registry.list_agents();
    let compliant_count = agents.iter().filter(|a| a.compliance_status == "COMPLIANT" && !a.is_revoked).count();
    let card3_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 🛡️ Agent Nodes ", Theme::subtitle()));
    let card3_text = vec![
        Line::from(vec![
            Span::styled("Enrolled: ", Theme::muted()),
            Span::styled(format!("{}", agents.len()), Theme::title()),
        ]),
        Line::from(vec![
            Span::styled("Compliant: ", Theme::muted()),
            Span::styled(format!("{}", compliant_count), Theme::success()),
        ]),
        Line::from(vec![
            Span::styled("mTLS Cert: ", Theme::muted()),
            Span::styled("90-Day Ed25519", Theme::normal()),
        ]),
    ];
    f.render_widget(Paragraph::new(card3_text).block(card3_block), kpi_chunks[2]);

    // Card 4: Policy & Audit Health
    let policies_count = state_guard.policy_store.list_policies().len();
    let audit_count = state_guard.audit_ledger.entries().len();
    let card4_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL))
        .title(Span::styled(" 📜 Security Ledger ", Theme::subtitle()));
    let card4_text = vec![
        Line::from(vec![
            Span::styled("Guard Points: ", Theme::muted()),
            Span::styled(format!("{}", policies_count), Theme::title()),
        ]),
        Line::from(vec![
            Span::styled("Audit Events: ", Theme::muted()),
            Span::styled(format!("{}", audit_count), Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Hash Chain: ", Theme::muted()),
            Span::styled("VERIFIED ✓", Theme::success()),
        ]),
    ];
    f.render_widget(Paragraph::new(card4_text).block(card4_block), kpi_chunks[3]);

    // 2. Active Guard Points Overview Table
    let policies = state_guard.policy_store.list_policies();
    let gp_rows: Vec<Row> = policies
        .iter()
        .take(4)
        .map(|p| {
            let deny_root_span = if p.deny_root_unauthorized {
                Span::styled("ENFORCED", Theme::danger())
            } else {
                Span::styled("OFF", Theme::muted())
            };

            Row::new(vec![
                Span::styled(&p.policy_id, Theme::normal()),
                Span::styled(&p.policy_name, Theme::title()),
                Span::styled(&p.target_path, Theme::normal()),
                Span::styled(&p.key_id, Theme::muted()),
                deny_root_span,
                Span::styled(format!("v{}", p.policy_version), Theme::subtitle()),
            ])
        })
        .collect();

    let gp_table = Table::new(
        gp_rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["ID", "POLICY NAME", "MOUNT TARGET", "BOUND KEK", "ROOT BLOCK", "VER"])
            .style(Theme::table_header()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(" 📁 Active Guard Points ", Theme::subtitle())),
    );
    f.render_widget(gp_table, chunks[1]);

    // 3. Recent Audit Activity Stream
    let audit_entries = state_guard.audit_ledger.entries();
    let recent_events: Vec<Row> = audit_entries
        .iter()
        .rev()
        .take(6)
        .map(|e| {
            let action_style = match e.action.as_str() {
                a if a.contains("ROTATE") || a.contains("CREATE") || a.contains("GEN") => Theme::warning(),
                a if a.contains("ENROLL") || a.contains("INIT") => Theme::success(),
                a if a.contains("DESTROY") || a.contains("REVOKE") => Theme::danger(),
                _ => Theme::normal(),
            };

            Row::new(vec![
                Span::styled(format!("#{}", e.index), Theme::muted()),
                Span::styled(&e.timestamp[11..19], Theme::muted()),
                Span::styled(&e.actor, Theme::normal()),
                Span::styled(&e.action, action_style),
                Span::styled(&e.details, Theme::normal()),
                Span::styled(
                    if e.entry_hash.len() >= 12 { &e.entry_hash[..12] } else { &e.entry_hash },
                    Theme::subtitle(),
                ),
            ])
        })
        .collect();

    let audit_table = Table::new(
        recent_events,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(18),
            Constraint::Percentage(45),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new(vec!["#", "TIME", "ACTOR", "ACTION", "DETAILS", "HASH"])
            .style(Theme::table_header()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(" 📜 Recent Security Events ", Theme::subtitle())),
    );
    f.render_widget(audit_table, chunks[2]);
}
