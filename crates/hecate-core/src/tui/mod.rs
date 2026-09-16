pub mod app;
pub mod modals;
pub mod theme;
pub mod views;

use anyhow::Result;
use app::{ActiveTab, ModalState, TuiApp};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hecate_crypto::SecretBuffer;
use hecate_protocol::policy::{GuardPointPolicy, PermissionAction, PolicyRule, PolicySubject, SubjectType};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub async fn run_tui(core_state: Arc<RwLock<crate::server::CoreState>>) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(core_state);

    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("TUI Error: {:?}", err);
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> Result<()> {
    let tick_rate = Duration::from_millis(250);

    loop {
        // Auto-reload state & check notification expiry
        {
            let mut state = app.core_state.write().await;
            state.reload_from_disk();
        }
        app.check_notification_expiry();

        // Render UI
        {
            let core_state_arc = app.core_state.clone();
            let state = core_state_arc.read().await;
            terminal.draw(|f| views::render_ui(f, app, &state))?;
        }

        // Poll for events
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // If modal is active, pass input to modal handler
                if handle_modal_input(app, key.code, key.modifiers).await? {
                    continue;
                }

                // Global Navigation and Shortcuts
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('?') => {
                        app.modal = ModalState::Help;
                    }
                    KeyCode::Tab => {
                        app.toggle_focus();
                    }
                    KeyCode::Char('1') => app.switch_tab(ActiveTab::Overview),
                    KeyCode::Char('2') => app.switch_tab(ActiveTab::Agents),
                    KeyCode::Char('3') => app.switch_tab(ActiveTab::Keys),
                    KeyCode::Char('4') => app.switch_tab(ActiveTab::GuardPoints),
                    KeyCode::Char('5') => app.switch_tab(ActiveTab::Audit),
                    KeyCode::Char('6') => app.switch_tab(ActiveTab::Recovery),

                    // Navigation
                    KeyCode::Down | KeyCode::Char('j') => {
                        let count = {
                            let state = app.core_state.read().await;
                            match app.active_tab {
                                ActiveTab::Overview => 0,
                                ActiveTab::Agents => state.agent_registry.list_agents().len(),
                                ActiveTab::Keys => state.hsm.list_keys().len(),
                                ActiveTab::GuardPoints => state.policy_store.list_policies().len(),
                                ActiveTab::Audit => state.audit_ledger.entries().len(),
                                ActiveTab::Recovery => 0,
                            }
                        };
                        app.next_item(count);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let count = {
                            let state = app.core_state.read().await;
                            match app.active_tab {
                                ActiveTab::Overview => 0,
                                ActiveTab::Agents => state.agent_registry.list_agents().len(),
                                ActiveTab::Keys => state.hsm.list_keys().len(),
                                ActiveTab::GuardPoints => state.policy_store.list_policies().len(),
                                ActiveTab::Audit => state.audit_ledger.entries().len(),
                                ActiveTab::Recovery => 0,
                            }
                        };
                        app.prev_item(count);
                    }

                    // Context-Specific Actions
                    KeyCode::Char('n') => match app.active_tab {
                        ActiveTab::Agents => {
                            app.modal = ModalState::GenerateToken {
                                hostname: "node-prod-01".to_string(),
                                ttl_secs: "3600".to_string(),
                                generated_token: None,
                                focus_idx: 0,
                            };
                        }
                        ActiveTab::Keys => {
                            app.modal = ModalState::CreateKey {
                                alias: "app-db-kek".to_string(),
                                key_type_idx: 0,
                            };
                        }
                        ActiveTab::GuardPoints => {
                            let first_key = {
                                let state = app.core_state.read().await;
                                state
                                    .hsm
                                    .list_keys()
                                    .first()
                                    .map(|k| k.key_id.clone())
                                    .unwrap_or_else(|| "key-default".to_string())
                            };

                            app.modal = ModalState::CreatePolicy {
                                id: format!("gp-{}", chrono::Utc::now().timestamp_subsec_millis()),
                                name: "Production DB Mount".to_string(),
                                target_path: "/data/secure_mount".to_string(),
                                backing_path: "/data/backing_store".to_string(),
                                key_id: first_key,
                                deny_root: true,
                                uid: "1000".to_string(),
                                focus_idx: 0,
                            };
                        }
                        _ => {}
                    },

                    KeyCode::Char('r') => match app.active_tab {
                        ActiveTab::Keys => {
                            let key_info = {
                                let state = app.core_state.read().await;
                                let keys = state.hsm.list_keys();
                                app.keys_table_state.selected().and_then(|idx| keys.get(idx).cloned())
                            };
                            if let Some(k) = key_info {
                                app.modal = ModalState::RotateKeyConfirm {
                                    key_id: k.key_id,
                                    alias: k.key_alias,
                                };
                            }
                        }
                        ActiveTab::Agents => {
                            let agent_info = {
                                let state = app.core_state.read().await;
                                let agents = state.agent_registry.list_agents();
                                app.agents_table_state.selected().and_then(|idx| agents.get(idx).cloned())
                            };
                            if let Some(a) = agent_info {
                                app.modal = ModalState::RevokeAgentConfirm {
                                    agent_id: a.agent_id,
                                    hostname: a.hostname,
                                };
                            }
                        }
                        _ => {}
                    },

                    KeyCode::Char('a') => {
                        if app.active_tab == ActiveTab::GuardPoints {
                            let policy_info = {
                                let state = app.core_state.read().await;
                                let policies = state.policy_store.list_policies();
                                app.policies_table_state.selected().and_then(|idx| policies.get(idx).cloned())
                            };
                            if let Some(p) = policy_info {
                                app.modal = ModalState::AddRule {
                                    policy_id: p.policy_id,
                                    rule_id: format!("rule-{}", p.rules.len() + 1),
                                    subject_type_idx: 0,
                                    identifier: "1000".to_string(),
                                    action_idx: 0,
                                    allow: true,
                                    focus_idx: 0,
                                };
                            }
                        }
                    }

                    KeyCode::Char('v') => {
                        if app.active_tab == ActiveTab::Audit || app.active_tab == ActiveTab::Overview {
                            let (is_valid, msg) = {
                                let state = app.core_state.read().await;
                                match state.audit_ledger.verify_chain() {
                                    Ok(_) => (true, "Cryptographic Audit Hash Chain Verified: 100% Intact ✓".to_string()),
                                    Err(e) => (false, format!("Audit Chain Broken: {}", e)),
                                }
                            };
                            app.audit_verified = is_valid;
                            app.set_notification(msg, !is_valid);
                        }
                    }

                    KeyCode::Char('b') => {
                        if app.active_tab == ActiveTab::Recovery {
                            app.modal = ModalState::CreateBackupConfirm;
                        }
                    }

                    KeyCode::Enter => {
                        if app.active_tab == ActiveTab::Audit {
                            let entry_info = {
                                let state = app.core_state.read().await;
                                let entries = state.audit_ledger.entries();
                                app.audit_table_state.selected().and_then(|idx| entries.get(idx).cloned())
                            };
                            if let Some(e) = entry_info {
                                let json_str = serde_json::to_string_pretty(&e).unwrap_or_default();
                                app.modal = ModalState::EntryDetails {
                                    title: format!("Audit Event #{} ({})", e.index, e.action),
                                    json_content: json_str,
                                };
                            }
                        }
                    }

                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

async fn handle_modal_input(app: &mut TuiApp, key: KeyCode, _modifiers: KeyModifiers) -> Result<bool> {
    if matches!(app.modal, ModalState::None) {
        return Ok(false);
    }

    if key == KeyCode::Esc {
        app.modal = ModalState::None;
        return Ok(true);
    }

    let mut current_modal = std::mem::replace(&mut app.modal, ModalState::None);
    let core_state = app.core_state.clone();

    match &mut current_modal {
        ModalState::None => {}

        ModalState::Help | ModalState::EntryDetails { .. } => {
            if key == KeyCode::Enter || key == KeyCode::Esc {
                app.modal = ModalState::None;
            } else {
                app.modal = current_modal;
            }
        }

        ModalState::CreateKey { alias, key_type_idx } => match key {
            KeyCode::Char(' ') | KeyCode::Tab => {
                *key_type_idx = (*key_type_idx + 1) % 3;
                app.modal = current_modal;
            }
            KeyCode::Backspace => {
                alias.pop();
                app.modal = current_modal;
            }
            KeyCode::Char(c) => {
                alias.push(c);
                app.modal = current_modal;
            }
            KeyCode::Enter => {
                let alias_copy = alias.clone();
                let kt = match *key_type_idx {
                    0 => hecate_crypto::KeyType::Aes256Gcm,
                    1 => hecate_crypto::KeyType::ChaCha20Poly1305,
                    _ => hecate_crypto::KeyType::HmacSha256,
                };

                let mut state = core_state.write().await;
                match state.hsm.generate_key(&alias_copy, kt, HashMap::new()) {
                    Ok(meta) => {
                        let _ = state.audit_ledger.append(
                            "TUI_GENERATE_KEY",
                            "admin-tui",
                            &format!("Key ID: {}, Alias: {}", meta.key_id, meta.key_alias),
                        );
                        let _ = state.persist();
                        app.set_notification(format!("Created Key '{}' ({})", meta.key_alias, meta.key_id), false);
                    }
                    Err(e) => {
                        app.set_notification(format!("Error creating key: {}", e), true);
                    }
                }
                app.modal = ModalState::None;
            }
            _ => {
                app.modal = current_modal;
            }
        },

        ModalState::RotateKeyConfirm { key_id, alias } => {
            if key == KeyCode::Enter {
                let kid = key_id.clone();
                let alias_copy = alias.clone();
                let mut state = core_state.write().await;
                match state.hsm.rotate_key(&kid) {
                    Ok(new_ver) => {
                        let _ = state.audit_ledger.append(
                            "TUI_ROTATE_KEY",
                            "admin-tui",
                            &format!("Rotated Key: {}, New Version: {}", kid, new_ver),
                        );
                        let _ = state.persist();
                        app.set_notification(format!("Key '{}' rotated to version {}", alias_copy, new_ver), false);
                    }
                    Err(e) => {
                        app.set_notification(format!("Rotation failed: {}", e), true);
                    }
                }
                app.modal = ModalState::None;
            } else {
                app.modal = current_modal;
            }
        }

        ModalState::GenerateToken { hostname, ttl_secs, generated_token, focus_idx } => match key {
            KeyCode::Tab => {
                *focus_idx = (*focus_idx + 1) % 2;
                app.modal = current_modal;
            }
            KeyCode::Backspace => {
                if *focus_idx == 0 {
                    hostname.pop();
                } else {
                    ttl_secs.pop();
                }
                app.modal = current_modal;
            }
            KeyCode::Char(c) => {
                if *focus_idx == 0 {
                    hostname.push(c);
                } else if c.is_ascii_digit() {
                    ttl_secs.push(c);
                }
                app.modal = current_modal;
            }
            KeyCode::Enter => {
                if generated_token.is_some() {
                    app.modal = ModalState::None;
                } else {
                    let ttl: i64 = ttl_secs.parse().unwrap_or(3600);
                    let mut state = core_state.write().await;
                    let token_obj = state.agent_registry.generate_token(hostname, ttl);
                    let _ = state.audit_ledger.append(
                        "TUI_GEN_TOKEN",
                        "admin-tui",
                        &format!("OTET generated for {}", hostname),
                    );
                    let _ = state.persist();
                    *generated_token = Some(token_obj.token);
                    app.set_notification(format!("Generated OTET token for {}", hostname), false);
                    app.modal = current_modal;
                }
            }
            _ => {
                app.modal = current_modal;
            }
        },

        ModalState::RevokeAgentConfirm { agent_id, hostname } => {
            if key == KeyCode::Enter {
                let aid = agent_id.clone();
                let hname = hostname.clone();
                let mut state = core_state.write().await;
                match state.agent_registry.revoke_agent(&aid) {
                    Ok(_) => {
                        let _ = state.audit_ledger.append(
                            "TUI_REVOKE_AGENT",
                            "admin-tui",
                            &format!("Revoked Agent: {} ({})", hname, aid),
                        );
                        let _ = state.persist();
                        app.set_notification(format!("Revoked certificate for agent '{}'", hname), false);
                    }
                    Err(e) => {
                        app.set_notification(format!("Revocation error: {}", e), true);
                    }
                }
                app.modal = ModalState::None;
            } else {
                app.modal = current_modal;
            }
        }

        ModalState::CreatePolicy { id, name, target_path, backing_path, key_id, deny_root, uid, focus_idx } => match key {
            KeyCode::Tab => {
                *focus_idx = (*focus_idx + 1) % 7;
                app.modal = current_modal;
            }
            KeyCode::Char(' ') if *focus_idx == 6 => {
                *deny_root = !*deny_root;
                app.modal = current_modal;
            }
            KeyCode::Backspace => {
                match *focus_idx {
                    0 => { id.pop(); }
                    1 => { name.pop(); }
                    2 => { target_path.pop(); }
                    3 => { backing_path.pop(); }
                    4 => { key_id.pop(); }
                    5 => { uid.pop(); }
                    _ => {}
                }
                app.modal = current_modal;
            }
            KeyCode::Char(c) => {
                match *focus_idx {
                    0 => { id.push(c); }
                    1 => { name.push(c); }
                    2 => { target_path.push(c); }
                    3 => { backing_path.push(c); }
                    4 => { key_id.push(c); }
                    5 => { uid.push(c); }
                    _ => {}
                }
                app.modal = current_modal;
            }
            KeyCode::Enter => {
                let policy = GuardPointPolicy {
                    policy_id: id.clone(),
                    policy_name: name.clone(),
                    target_path: target_path.clone(),
                    backing_path: backing_path.clone(),
                    key_id: key_id.clone(),
                    deny_root_unauthorized: *deny_root,
                    rules: vec![PolicyRule {
                        rule_id: "rule-default-uid".to_string(),
                        subjects: vec![PolicySubject {
                            subject_type: SubjectType::Uid as i32,
                            identifier: uid.clone(),
                        }],
                        action: PermissionAction::ActionReadWrite as i32,
                        allow: true,
                    }],
                    policy_version: 1,
                    updated_at: chrono::Utc::now().timestamp(),
                };

                let mut state = core_state.write().await;
                state.policy_store.add_or_update_policy(policy);
                let _ = state.audit_ledger.append("TUI_ADD_POLICY", "admin-tui", &format!("Policy: {}", id));
                let _ = state.persist();
                app.set_notification(format!("Registered Guard Point Policy '{}'", id), false);
                app.modal = ModalState::None;
            }
            _ => {
                app.modal = current_modal;
            }
        },

        ModalState::AddRule { policy_id, rule_id, subject_type_idx, identifier, action_idx, allow, focus_idx } => match key {
            KeyCode::Tab => {
                *focus_idx = (*focus_idx + 1) % 5;
                app.modal = current_modal;
            }
            KeyCode::Char(' ') => {
                if *focus_idx == 1 {
                    *subject_type_idx = (*subject_type_idx + 1) % 4;
                } else if *focus_idx == 3 {
                    *action_idx = (*action_idx + 1) % 3;
                } else if *focus_idx == 4 {
                    *allow = !*allow;
                }
                app.modal = current_modal;
            }
            KeyCode::Backspace => {
                if *focus_idx == 0 {
                    rule_id.pop();
                } else if *focus_idx == 2 {
                    identifier.pop();
                }
                app.modal = current_modal;
            }
            KeyCode::Char(c) => {
                if *focus_idx == 0 {
                    rule_id.push(c);
                } else if *focus_idx == 2 {
                    identifier.push(c);
                }
                app.modal = current_modal;
            }
            KeyCode::Enter => {
                let st = match *subject_type_idx {
                    0 => SubjectType::Uid,
                    1 => SubjectType::Gid,
                    2 => SubjectType::BinaryHash,
                    _ => SubjectType::User,
                };
                let act = match *action_idx {
                    0 => PermissionAction::ActionReadWrite,
                    1 => PermissionAction::ActionRead,
                    _ => PermissionAction::ActionWrite,
                };

                let rule = PolicyRule {
                    rule_id: rule_id.clone(),
                    subjects: vec![PolicySubject {
                        subject_type: st as i32,
                        identifier: identifier.clone(),
                    }],
                    action: act as i32,
                    allow: *allow,
                };

                let mut state = core_state.write().await;
                if let Some(p) = state.policy_store.get_policy_mut(policy_id) {
                    p.rules.push(rule);
                    p.policy_version += 1;
                    p.updated_at = chrono::Utc::now().timestamp();
                    let _ = state.audit_ledger.append("TUI_ADD_RULE", "admin-tui", &format!("Rule '{}' on policy {}", rule_id, policy_id));
                    let _ = state.persist();
                    app.set_notification(format!("Appended Rule '{}' to policy {}", rule_id, policy_id), false);
                }
                app.modal = ModalState::None;
            }
            _ => {
                app.modal = current_modal;
            }
        },

        ModalState::CreateBackupConfirm => {
            if key == KeyCode::Enter {
                let state = core_state.read().await;
                let backup_path = state.base_dir.join("hecate_dr_backup.hct");
                let payload = serde_json::to_vec(&state.vault_db)?;
                match crate::ha::backup::create_dr_backup(&payload, &SecretBuffer::from_str("disaster_recovery_master_pass")) {
                    Ok((archive, sha)) => {
                        fs::write(&backup_path, archive)?;
                        app.set_notification(format!("DR Backup Saved: {} (SHA: {})", backup_path.display(), &sha[..12]), false);
                    }
                    Err(e) => {
                        app.set_notification(format!("Backup failed: {}", e), true);
                    }
                }
                app.modal = ModalState::None;
            } else {
                app.modal = current_modal;
            }
        }
    }

    Ok(true)
}
