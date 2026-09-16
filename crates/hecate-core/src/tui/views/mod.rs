pub mod agents;
pub mod audit;
pub mod dashboard;
pub mod guardpoints;
pub mod keys;
pub mod recovery;
pub mod sidebar;

use crate::tui::app::{ActiveTab, FocusArea, TuiApp};
use crate::tui::modals::render_modals;
use crate::tui::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

pub fn render_ui(f: &mut Frame, app: &mut TuiApp, state_guard: &crate::server::CoreState) {
    let size = f.area();

    // Top Level Layout: Header (3) -> Body (Min 10) -> Footer (3)
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top Header Bar
            Constraint::Min(10),   // Split Body (Sidebar + Content)
            Constraint::Length(3), // Bottom Footer & Status Bar
        ])
        .split(size);

    // 1. Top Header Bar
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL));

    let active_section_name = match app.active_tab {
        ActiveTab::Overview => "EXECUTIVE OVERVIEW & POSTURE DASHBOARD",
        ActiveTab::Agents => "AGENT NODES & CLIENT ENDPOINT GOVERNANCE",
        ActiveTab::Keys => "SOFTWARE HSM KEY ENCRYPTION KEY (KEK) MANAGEMENT",
        ActiveTab::GuardPoints => "GUARD POINT POLICIES & ROOT CONTAINMENT RULES",
        ActiveTab::Audit => "TAMPER-EVIDENT SHA-256 HASH CHAIN AUDIT LEDGER",
        ActiveTab::Recovery => "DISASTER RECOVERY & SHAMIR M-OF-N CUSTODY",
    };

    let focus_str = match app.focus {
        FocusArea::Sidebar => "[Focus: SIDEBAR (Tabs)]",
        FocusArea::MainContent => "[Focus: MAIN WORKSPACE]",
    };

    let header_lines = vec![Line::from(vec![
        Span::styled(" 🛡️  HECATE VAULT  ", Theme::title()),
        Span::styled("│ ", Theme::muted()),
        Span::styled(active_section_name, Theme::subtitle()),
        Span::styled(format!("  {}  ", focus_str), Theme::shortcut_key()),
    ])];

    let header_p = Paragraph::new(header_lines).block(header_block);
    f.render_widget(header_p, main_chunks[0]);

    // 2. Split Body (Left Sidebar 26% vs Right Main Content 74%)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(30), // Fixed Sidebar Width
            Constraint::Min(40),    // Main Content View
        ])
        .split(main_chunks[1]);

    // Render Left Sidebar
    sidebar::render_sidebar(f, app, body_chunks[0], state_guard);

    // Render Right Main View according to Active Tab
    match app.active_tab {
        ActiveTab::Overview => dashboard::render_dashboard(f, app, body_chunks[1], state_guard),
        ActiveTab::Agents => agents::render_agents(f, app, body_chunks[1], state_guard),
        ActiveTab::Keys => keys::render_keys(f, app, body_chunks[1], state_guard),
        ActiveTab::GuardPoints => guardpoints::render_guardpoints(f, app, body_chunks[1], state_guard),
        ActiveTab::Audit => audit::render_audit(f, app, body_chunks[1], state_guard),
        ActiveTab::Recovery => recovery::render_recovery(f, app, body_chunks[1], state_guard),
    }

    // 3. Bottom Footer & Status Bar
    let footer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Theme::BORDER_NORMAL));

    let footer_line = if let Some(notif) = &app.notification {
        let style = if notif.is_error { Theme::danger() } else { Theme::success() };
        Line::from(vec![
            Span::styled(" 📢 NOTIFICATION: ", Theme::shortcut_key()),
            Span::styled(&notif.message, style),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [1-6/Tab] ", Theme::shortcut_key()),
            Span::styled("Switch Tabs  ", Theme::muted()),
            Span::styled("│ [↑/↓/j/k] ", Theme::shortcut_key()),
            Span::styled("Navigate  ", Theme::muted()),
            Span::styled("│ [n] ", Theme::shortcut_key()),
            Span::styled("New Item  ", Theme::muted()),
            Span::styled("│ [r] ", Theme::shortcut_key()),
            Span::styled("Rotate/Revoke  ", Theme::muted()),
            Span::styled("│ [?] ", Theme::shortcut_key()),
            Span::styled("Help  ", Theme::muted()),
            Span::styled("│ [q] ", Theme::shortcut_key()),
            Span::styled("Quit", Theme::muted()),
        ])
    };

    let footer_p = Paragraph::new(footer_line).block(footer_block);
    f.render_widget(footer_p, main_chunks[2]);

    // 4. Render Modals overlay on top if active
    render_modals(f, app, size);
}
