use crate::tui::app::{ModalState, TuiApp};
use crate::tui::theme::Theme;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn render_modals(f: &mut Frame, app: &TuiApp, area: Rect) {
    match &app.modal {
        ModalState::None => {}

        ModalState::Help => {
            let popup_area = centered_rect(60, 65, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(" 💡 Hecate Vault TUI Keyboard Shortcuts ", Theme::title()));

            let help_text = vec![
                Line::from(vec![
                    Span::styled("Navigation & Tabs:", Theme::subtitle()),
                ]),
                Line::from(vec![
                    Span::styled("  [1] - [6]       ", Theme::shortcut_key()),
                    Span::styled("Directly switch to section tab", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [Tab]           ", Theme::shortcut_key()),
                    Span::styled("Toggle focus between Sidebar and Main View", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [↑ / ↓ / j / k] ", Theme::shortcut_key()),
                    Span::styled("Navigate tables and rows", Theme::normal()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Item Management Actions:", Theme::subtitle()),
                ]),
                Line::from(vec![
                    Span::styled("  [n]             ", Theme::shortcut_key()),
                    Span::styled("New item (Create Key, Add Policy, Generate Agent Token)", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [r]             ", Theme::shortcut_key()),
                    Span::styled("Rotate Key Version / Revoke Agent Certificate", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [a]             ", Theme::shortcut_key()),
                    Span::styled("Add Rule to selected Guard Point policy", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [v]             ", Theme::shortcut_key()),
                    Span::styled("Re-verify Audit Hash Chain Integrity", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [b]             ", Theme::shortcut_key()),
                    Span::styled("Create Encrypted Disaster Recovery Backup (.hct)", Theme::normal()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("General:", Theme::subtitle()),
                ]),
                Line::from(vec![
                    Span::styled("  [?]             ", Theme::shortcut_key()),
                    Span::styled("Toggle this help popup", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [Esc]           ", Theme::shortcut_key()),
                    Span::styled("Close active modal dialog", Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("  [q] / [Ctrl+c]  ", Theme::shortcut_key()),
                    Span::styled("Quit Hecate Vault TUI", Theme::normal()),
                ]),
            ];

            let p = Paragraph::new(help_text).block(block);
            f.render_widget(p, popup_area);
        }

        ModalState::CreateKey { alias, key_type_idx } => {
            let popup_area = centered_rect(50, 40, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(" 🔑 Create New Key Encryption Key (KEK) ", Theme::title()));

            let algs = ["AES-256-GCM (Recommended)", "ChaCha20-Poly1305", "HMAC-SHA256"];
            let alg_str = algs[*key_type_idx];

            let form_lines = vec![
                Line::from(vec![
                    Span::styled("Key Alias (Name): ", Theme::muted()),
                    Span::styled(format!("{}_", alias), Theme::title()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Algorithm: ", Theme::muted()),
                    Span::styled(alg_str, Theme::success()),
                    Span::styled(" [Press Space/Tab to cycle]", Theme::muted()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Storage: Software HSM (Sealed in memory locked pages)", Theme::muted()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Create Key  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(form_lines).block(block).alignment(Alignment::Left);
            f.render_widget(p, popup_area);
        }

        ModalState::RotateKeyConfirm { key_id, alias } => {
            let popup_area = centered_rect(45, 30, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::WARNING))
                .title(Span::styled(" 🔄 Confirm KEK Version Rotation ", Theme::warning()));

            let text = vec![
                Line::from(vec![
                    Span::styled("Rotate Key: ", Theme::muted()),
                    Span::styled(alias, Theme::title()),
                    Span::styled(format!(" ({})", key_id), Theme::muted()),
                ]),
                Line::from(""),
                Line::from("This will generate a new 256-bit key version in the Software HSM."),
                Line::from("Old versions remain usable for decryption only."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Confirm Rotation  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(text).block(block).alignment(Alignment::Center);
            f.render_widget(p, popup_area);
        }

        ModalState::GenerateToken { hostname, ttl_secs, generated_token, focus_idx } => {
            let popup_area = centered_rect(55, 45, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(" 🛡️  Mint Agent Enrollment Token (OTET) ", Theme::title()));

            let mut form_lines = vec![
                Line::from(vec![
                    Span::styled("Client Node Hostname: ", Theme::muted()),
                    Span::styled(if *focus_idx == 0 { format!("{}_", hostname) } else { hostname.clone() }, Theme::title()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Token TTL (Seconds):  ", Theme::muted()),
                    Span::styled(if *focus_idx == 1 { format!("{}_", ttl_secs) } else { ttl_secs.clone() }, Theme::normal()),
                ]),
                Line::from(""),
            ];

            if let Some(token) = generated_token {
                form_lines.push(Line::from(vec![
                    Span::styled("✓ Generated Token: ", Theme::success()),
                    Span::styled(token, Theme::title()),
                ]));
                form_lines.push(Line::from("Run agent with: hecate-agent enroll --token <TOKEN>"));
                form_lines.push(Line::from(""));
                form_lines.push(Line::from(vec![
                    Span::styled("[Esc/Enter] Done", Theme::shortcut_key()),
                ]));
            } else {
                form_lines.push(Line::from(vec![
                    Span::styled("[Enter] Mint Token  |  [Tab] Switch Field  |  [Esc] Cancel", Theme::shortcut_key()),
                ]));
            }

            let p = Paragraph::new(form_lines).block(block);
            f.render_widget(p, popup_area);
        }

        ModalState::RevokeAgentConfirm { agent_id, hostname } => {
            let popup_area = centered_rect(45, 30, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::DANGER))
                .title(Span::styled(" ⚠️  Revoke Agent Client Certificate ", Theme::danger()));

            let text = vec![
                Line::from(vec![
                    Span::styled("Revoke Node: ", Theme::muted()),
                    Span::styled(hostname, Theme::title()),
                    Span::styled(format!(" ({})", agent_id), Theme::muted()),
                ]),
                Line::from(""),
                Line::from("The agent node certificate will be marked REVOKED immediately."),
                Line::from("Agent policy sync and key distribution will be rejected."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Confirm Revocation  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(text).block(block).alignment(Alignment::Center);
            f.render_widget(p, popup_area);
        }

        ModalState::CreatePolicy { id, name, target_path, backing_path, key_id, deny_root, uid, focus_idx } => {
            let popup_area = centered_rect(65, 60, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(" 📁 Create Guard Point Policy Wizard ", Theme::title()));

            let form_lines = vec![
                Line::from(vec![
                    Span::styled("1. Policy ID:    ", Theme::muted()),
                    Span::styled(if *focus_idx == 0 { format!("{}_", id) } else { id.clone() }, Theme::title()),
                ]),
                Line::from(vec![
                    Span::styled("2. Policy Name:  ", Theme::muted()),
                    Span::styled(if *focus_idx == 1 { format!("{}_", name) } else { name.clone() }, Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("3. Target Path:  ", Theme::muted()),
                    Span::styled(if *focus_idx == 2 { format!("{}_", target_path) } else { target_path.clone() }, Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("4. Backing Path: ", Theme::muted()),
                    Span::styled(if *focus_idx == 3 { format!("{}_", backing_path) } else { backing_path.clone() }, Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("5. Bound KEK ID: ", Theme::muted()),
                    Span::styled(if *focus_idx == 4 { format!("{}_", key_id) } else { key_id.clone() }, Theme::subtitle()),
                ]),
                Line::from(vec![
                    Span::styled("6. Allow UID:    ", Theme::muted()),
                    Span::styled(if *focus_idx == 5 { format!("{}_", uid) } else { uid.clone() }, Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("7. Deny Root:    ", Theme::muted()),
                    Span::styled(if *deny_root { "ENABLED (Strict Root Containment)" } else { "DISABLED" }, if *deny_root { Theme::danger() } else { Theme::muted() }),
                    Span::styled(" [Press Space on field 6 to toggle]", Theme::muted()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Create Policy  |  [Tab] Next Field  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(form_lines).block(block);
            f.render_widget(p, popup_area);
        }

        ModalState::AddRule { policy_id, rule_id, subject_type_idx, identifier, action_idx, allow, focus_idx } => {
            let popup_area = centered_rect(60, 50, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(format!(" 🛡️ Add Rule to Policy: {} ", policy_id), Theme::title()));

            let subjs = ["UID (User ID)", "GID (Group ID)", "Binary SHA-256 Digest", "Process Path"];
            let acts = ["Read/Write", "Read Only", "Execute"];

            let form_lines = vec![
                Line::from(vec![
                    Span::styled("Rule ID:      ", Theme::muted()),
                    Span::styled(if *focus_idx == 0 { format!("{}_", rule_id) } else { rule_id.clone() }, Theme::title()),
                ]),
                Line::from(vec![
                    Span::styled("Subject Type: ", Theme::muted()),
                    Span::styled(subjs[*subject_type_idx], Theme::normal()),
                    Span::styled(" [Press Space to cycle]", Theme::muted()),
                ]),
                Line::from(vec![
                    Span::styled("Identifier:   ", Theme::muted()),
                    Span::styled(if *focus_idx == 2 { format!("{}_", identifier) } else { identifier.clone() }, Theme::normal()),
                ]),
                Line::from(vec![
                    Span::styled("Action:       ", Theme::muted()),
                    Span::styled(acts[*action_idx], Theme::normal()),
                    Span::styled(" [Press Space to cycle]", Theme::muted()),
                ]),
                Line::from(vec![
                    Span::styled("Decision:     ", Theme::muted()),
                    Span::styled(if *allow { "ALLOW 🟢" } else { "DENY 🔴" }, if *allow { Theme::success() } else { Theme::danger() }),
                    Span::styled(" [Press Space to toggle]", Theme::muted()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Save Rule  |  [Tab] Next Field  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(form_lines).block(block);
            f.render_widget(p, popup_area);
        }

        ModalState::EntryDetails { title, json_content } => {
            let popup_area = centered_rect(70, 70, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(format!(" 🔍 {} ", title), Theme::title()));

            let p = Paragraph::new(json_content.as_str())
                .block(block)
                .style(Theme::normal());
            f.render_widget(p, popup_area);
        }

        ModalState::CreateBackupConfirm => {
            let popup_area = centered_rect(50, 30, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Theme::ACCENT))
                .title(Span::styled(" 💾 Create Disaster Recovery Backup ", Theme::title()));

            let text = vec![
                Line::from("Create encrypted full backup archive (.hct)?"),
                Line::from("This bundle encrypts the HSM state, vault secrets, PKI CA, and audit log."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("[Enter] Generate Backup  |  [Esc] Cancel", Theme::shortcut_key()),
                ]),
            ];

            let p = Paragraph::new(text).block(block).alignment(Alignment::Center);
            f.render_widget(p, popup_area);
        }
    }
}
