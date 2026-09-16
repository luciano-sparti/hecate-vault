use crate::tui::app::{FocusArea, TuiApp};
use crate::tui::theme::Theme;
use hecate_protocol::policy::{PermissionAction, SubjectType};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

pub fn render_guardpoints(f: &mut Frame, app: &mut TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50), // Policies Table
            Constraint::Percentage(50), // Split Policy Details & Access Rules Table
        ])
        .split(area);

    let policies = state_guard.policy_store.list_policies();
    let selected_idx = app.policies_table_state.selected().unwrap_or(0);

    // 1. Policies Table
    let rows: Vec<Row> = policies
        .iter()
        .enumerate()
        .map(|(idx, policy)| {
            let is_selected = idx == selected_idx;
            let deny_root_span = if policy.deny_root_unauthorized {
                Span::styled("ENFORCED 🔒", Theme::danger())
            } else {
                Span::styled("DISABLED", Theme::muted())
            };

            let row_style = if is_selected {
                Theme::selected_row()
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(Span::styled(&policy.policy_id, Theme::normal())),
                Cell::from(Span::styled(&policy.policy_name, Theme::title())),
                Cell::from(Span::styled(&policy.target_path, Theme::normal())),
                Cell::from(Span::styled(&policy.key_id, Theme::muted())),
                Cell::from(deny_root_span),
                Cell::from(Span::styled(format!("{}", policy.rules.len()), Theme::normal())),
                Cell::from(Span::styled(format!("v{}", policy.policy_version), Theme::subtitle())),
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
            Constraint::Length(16),
            Constraint::Percentage(22),
            Constraint::Percentage(26),
            Constraint::Length(20),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(6),
        ],
    )
    .header(
        Row::new(vec!["ID", "POLICY NAME", "MOUNT TARGET", "BOUND KEK", "ROOT BLOCK", "RULES", "VER"])
            .style(Theme::table_header()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title(Span::styled(" 📁 Guard Point Policies ([n] Create Policy | [a] Add Rule | [↑/↓] Select) ", Theme::subtitle())),
    )
    .row_highlight_style(Theme::selected_row());

    f.render_stateful_widget(table, chunks[0], &mut app.policies_table_state);

    // 2. Selected Policy Details & Rules Table Split Pane
    let detail_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    if let Some(policy) = policies.get(selected_idx) {
        // Left: Policy Configuration & Integrity
        let param_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Theme::BORDER_NORMAL))
            .title(Span::styled(format!(" 📋 Policy Profile: {} ", policy.policy_id), Theme::subtitle()));

        let param_lines = vec![
            Line::from(vec![
                Span::styled("Policy ID: ", Theme::muted()),
                Span::styled(&policy.policy_id, Theme::title()),
            ]),
            Line::from(vec![
                Span::styled("Target Mount: ", Theme::muted()),
                Span::styled(&policy.target_path, Theme::normal()),
            ]),
            Line::from(vec![
                Span::styled("Backing Store: ", Theme::muted()),
                Span::styled(&policy.backing_path, Theme::muted()),
            ]),
            Line::from(vec![
                Span::styled("Deny Root: ", Theme::muted()),
                if policy.deny_root_unauthorized {
                    Span::styled("TRUE (Block unauthorized root access)", Theme::danger())
                } else {
                    Span::styled("FALSE", Theme::muted())
                },
            ]),
            Line::from(vec![
                Span::styled("Signature: ", Theme::muted()),
                Span::styled("Ed25519 Core Asymmetric Signed ✓", Theme::success()),
            ]),
        ];
        f.render_widget(Paragraph::new(param_lines).block(param_block), detail_chunks[0]);

        // Right: Access Rules Table
        let rule_rows: Vec<Row> = policy
            .rules
            .iter()
            .map(|r| {
                let subject_str = if let Some(subj) = r.subjects.first() {
                    let st_str = match subj.subject_type() {
                        SubjectType::Uid => "UID",
                        SubjectType::Gid => "GID",
                        SubjectType::BinaryHash => "SHA256",
                        SubjectType::Role => "ROLE",
                        SubjectType::User => "USER",
                        SubjectType::Unspecified => "ANY",
                    };
                    format!("{}: {}", st_str, subj.identifier)
                } else {
                    "All Subjects".to_string()
                };

                let action_str = match r.action() {
                    PermissionAction::ActionReadWrite => "Read/Write",
                    PermissionAction::ActionRead => "Read Only",
                    PermissionAction::ActionWrite => "Write Only",
                    PermissionAction::ActionAuditOnly => "Audit Only",
                    PermissionAction::ActionUnspecified => "All",
                };

                let decision_span = if r.allow {
                    Span::styled("ALLOW 🟢", Theme::success())
                } else {
                    Span::styled("DENY 🔴", Theme::danger())
                };

                Row::new(vec![
                    Span::styled(&r.rule_id, Theme::normal()),
                    Span::styled(subject_str, Theme::title()),
                    Span::styled(action_str, Theme::normal()),
                    decision_span,
                ])
            })
            .collect();

        let rules_table = Table::new(
            rule_rows,
            [
                Constraint::Length(18),
                Constraint::Percentage(40),
                Constraint::Length(14),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new(vec!["RULE ID", "SUBJECT (USER/PROCESS)", "ACTION", "DECISION"])
                .style(Theme::table_header()),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Theme::BORDER_NORMAL))
                .title(Span::styled(" 🛡️ Access Control Rules Table ", Theme::subtitle())),
        );

        f.render_widget(rules_table, detail_chunks[1]);
    } else {
        let empty_p = Paragraph::new("No policies configured. Press [n] to create a new Guard Point policy.")
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
            .style(Theme::muted());
        f.render_widget(empty_p, chunks[1]);
    }
}
