use crate::server::CoreState;
use ratatui::widgets::TableState;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Overview = 0,
    Agents = 1,
    Keys = 2,
    GuardPoints = 3,
    Audit = 4,
    Recovery = 5,
}

impl ActiveTab {
    pub const ALL: [ActiveTab; 6] = [
        ActiveTab::Overview,
        ActiveTab::Agents,
        ActiveTab::Keys,
        ActiveTab::GuardPoints,
        ActiveTab::Audit,
        ActiveTab::Recovery,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            ActiveTab::Overview => "1. 📊 Overview",
            ActiveTab::Agents => "2. 🛡️  Agents & Clients",
            ActiveTab::Keys => "3. 🔑 Key Management",
            ActiveTab::GuardPoints => "4. 📁 Guard Points",
            ActiveTab::Audit => "5. 📜 Audit Ledger",
            ActiveTab::Recovery => "6. 🛟 Disaster Recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    MainContent,
}

#[derive(Debug, Clone)]
pub enum ModalState {
    None,
    Help,
    GenerateToken {
        hostname: String,
        ttl_secs: String,
        generated_token: Option<String>,
        focus_idx: usize,
    },
    RevokeAgentConfirm {
        agent_id: String,
        hostname: String,
    },
    CreateKey {
        alias: String,
        key_type_idx: usize, // 0: AES-256-GCM, 1: ChaCha20-Poly1305, 2: HMAC-SHA256
    },
    RotateKeyConfirm {
        key_id: String,
        alias: String,
    },
    CreatePolicy {
        id: String,
        name: String,
        target_path: String,
        backing_path: String,
        key_id: String,
        deny_root: bool,
        uid: String,
        focus_idx: usize,
    },
    AddRule {
        policy_id: String,
        rule_id: String,
        subject_type_idx: usize, // 0: UID, 1: GID, 2: Binary Digest, 3: Process Path
        identifier: String,
        action_idx: usize,       // 0: ReadWrite, 1: ReadOnly, 2: Exec
        allow: bool,
        focus_idx: usize,
    },
    EntryDetails {
        title: String,
        json_content: String,
    },
    CreateBackupConfirm,
}

pub struct Notification {
    pub message: String,
    pub is_error: bool,
    pub created_at: Instant,
}

pub struct TuiApp {
    pub core_state: Arc<RwLock<CoreState>>,
    pub active_tab: ActiveTab,
    pub focus: FocusArea,
    pub modal: ModalState,
    pub notification: Option<Notification>,
    pub should_quit: bool,

    // Selection states
    pub agents_table_state: TableState,
    pub keys_table_state: TableState,
    pub policies_table_state: TableState,
    pub audit_table_state: TableState,

    // Sub-item rule table state inside policies
    pub policy_rules_state: TableState,

    // Audit chain verified flag
    pub audit_verified: bool,
}

impl TuiApp {
    pub fn new(core_state: Arc<RwLock<CoreState>>) -> Self {
        let mut app = Self {
            core_state,
            active_tab: ActiveTab::Overview,
            focus: FocusArea::Sidebar,
            modal: ModalState::None,
            notification: None,
            should_quit: false,
            agents_table_state: TableState::default(),
            keys_table_state: TableState::default(),
            policies_table_state: TableState::default(),
            audit_table_state: TableState::default(),
            policy_rules_state: TableState::default(),
            audit_verified: true,
        };

        app.agents_table_state.select(Some(0));
        app.keys_table_state.select(Some(0));
        app.policies_table_state.select(Some(0));
        app.audit_table_state.select(Some(0));
        app.policy_rules_state.select(Some(0));

        app
    }

    pub fn set_notification(&mut self, message: impl Into<String>, is_error: bool) {
        self.notification = Some(Notification {
            message: message.into(),
            is_error,
            created_at: Instant::now(),
        });
    }

    pub fn check_notification_expiry(&mut self) {
        if let Some(notif) = &self.notification {
            if notif.created_at.elapsed().as_secs() > 4 {
                self.notification = None;
            }
        }
    }

    pub fn switch_tab(&mut self, tab: ActiveTab) {
        self.active_tab = tab;
        self.focus = FocusArea::MainContent;
    }

    pub fn next_tab(&mut self) {
        let idx = (self.active_tab as usize + 1) % ActiveTab::ALL.len();
        self.active_tab = ActiveTab::ALL[idx];
    }

    pub fn prev_tab(&mut self) {
        let len = ActiveTab::ALL.len();
        let idx = (self.active_tab as usize + len - 1) % len;
        self.active_tab = ActiveTab::ALL[idx];
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            FocusArea::Sidebar => FocusArea::MainContent,
            FocusArea::MainContent => FocusArea::Sidebar,
        };
    }

    pub fn next_item(&mut self, max_len: usize) {
        if max_len == 0 {
            return;
        }
        match self.active_tab {
            ActiveTab::Overview => {}
            ActiveTab::Agents => {
                let curr = self.agents_table_state.selected().unwrap_or(0);
                self.agents_table_state.select(Some((curr + 1) % max_len));
            }
            ActiveTab::Keys => {
                let curr = self.keys_table_state.selected().unwrap_or(0);
                self.keys_table_state.select(Some((curr + 1) % max_len));
            }
            ActiveTab::GuardPoints => {
                let curr = self.policies_table_state.selected().unwrap_or(0);
                self.policies_table_state.select(Some((curr + 1) % max_len));
            }
            ActiveTab::Audit => {
                let curr = self.audit_table_state.selected().unwrap_or(0);
                self.audit_table_state.select(Some((curr + 1) % max_len));
            }
            ActiveTab::Recovery => {}
        }
    }

    pub fn prev_item(&mut self, max_len: usize) {
        if max_len == 0 {
            return;
        }
        match self.active_tab {
            ActiveTab::Overview => {}
            ActiveTab::Agents => {
                let curr = self.agents_table_state.selected().unwrap_or(0);
                self.agents_table_state.select(Some((curr + max_len - 1) % max_len));
            }
            ActiveTab::Keys => {
                let curr = self.keys_table_state.selected().unwrap_or(0);
                self.keys_table_state.select(Some((curr + max_len - 1) % max_len));
            }
            ActiveTab::GuardPoints => {
                let curr = self.policies_table_state.selected().unwrap_or(0);
                self.policies_table_state.select(Some((curr + max_len - 1) % max_len));
            }
            ActiveTab::Audit => {
                let curr = self.audit_table_state.selected().unwrap_or(0);
                self.audit_table_state.select(Some((curr + max_len - 1) % max_len));
            }
            ActiveTab::Recovery => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_or_init_core_state;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_tui_app_navigation_and_modals() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let core_state = load_or_init_core_state(temp_dir.path())?;
        let mut app = TuiApp::new(core_state);

        // 1. Initial State
        assert_eq!(app.active_tab, ActiveTab::Overview);
        assert_eq!(app.focus, FocusArea::Sidebar);
        assert!(matches!(app.modal, ModalState::None));

        // 2. Tab Navigation
        app.switch_tab(ActiveTab::Agents);
        assert_eq!(app.active_tab, ActiveTab::Agents);
        assert_eq!(app.focus, FocusArea::MainContent);

        app.next_tab();
        assert_eq!(app.active_tab, ActiveTab::Keys);

        app.prev_tab();
        assert_eq!(app.active_tab, ActiveTab::Agents);

        // 3. Item Selection
        app.next_item(5);
        assert_eq!(app.agents_table_state.selected(), Some(1));
        app.prev_item(5);
        assert_eq!(app.agents_table_state.selected(), Some(0));

        // 4. Notifications
        app.set_notification("Key Generated", false);
        assert!(app.notification.is_some());
        assert_eq!(app.notification.as_ref().unwrap().message, "Key Generated");
        assert!(!app.notification.as_ref().unwrap().is_error);

        // 5. Toggle Focus
        app.toggle_focus();
        assert_eq!(app.focus, FocusArea::Sidebar);
        app.toggle_focus();
        assert_eq!(app.focus, FocusArea::MainContent);

        Ok(())
    }
}
