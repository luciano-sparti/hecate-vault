use crate::tui::app::{ActiveTab, FocusArea, TuiApp};
use crate::tui::theme::Theme;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render_sidebar(f: &mut Frame, app: &TuiApp, area: Rect, state_guard: &crate::server::CoreState) {
    let border_style = if app.focus == FocusArea::Sidebar {
        Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Theme::BORDER_NORMAL)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Brand Header
            Constraint::Min(10),    // Navigation List
            Constraint::Length(7),  // System Telemetry Widget
        ])
        .split(area);

    // 1. Brand Header
    let brand_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(" 🛡️ HECATE VAULT ", Theme::title()));

    let brand_text = vec![
        Line::from(vec![
            Span::styled("Soft-HSM: ", Theme::muted()),
            Span::styled("ACTIVE 🟢", Theme::success()),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Theme::muted()),
            Span::styled("v0.2.0 (mTLS)", Theme::subtitle()),
        ]),
    ];
    let brand_p = Paragraph::new(brand_text).block(brand_block).alignment(Alignment::Center);
    f.render_widget(brand_p, chunks[0]);

    // 2. Navigation Items
    let items: Vec<ListItem> = ActiveTab::ALL
        .iter()
        .map(|tab| {
            let is_selected = *tab == app.active_tab;
            let (bg, fg, prefix) = if is_selected {
                (Color::Rgb(49, 46, 129), Color::White, " ▶ ")
            } else {
                (Color::Reset, Color::Rgb(199, 210, 254), "   ")
            };

            let content = Line::from(vec![
                Span::styled(prefix, Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)),
                Span::styled(tab.title(), Style::default().fg(fg).add_modifier(if is_selected { Modifier::BOLD } else { Modifier::empty() })),
            ]);

            ListItem::new(content).style(Style::default().bg(bg))
        })
        .collect();

    let nav_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(" SECTIONS ", Theme::subtitle()));

    let list = List::new(items).block(nav_block);
    f.render_widget(list, chunks[1]);

    // 3. System Telemetry Widget
    let telemetry_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(" 🔒 TELEMETRY ", Theme::subtitle()));

    let trust_provider = &state_guard.vault_db.root_provider;
    let chain_status = if app.audit_verified {
        Span::styled("VALID ✓", Theme::success())
    } else {
        Span::styled("TAMPER ✗", Theme::danger())
    };

    let telemetry_text = vec![
        Line::from(vec![
            Span::styled("Root Trust: ", Theme::muted()),
            Span::styled(trust_provider.to_uppercase(), Theme::normal()),
        ]),
        Line::from(vec![
            Span::styled("Page Lock: ", Theme::muted()),
            Span::styled("mlock [ON]", Theme::success()),
        ]),
        Line::from(vec![
            Span::styled("Audit Chain: ", Theme::muted()),
            chain_status,
        ]),
    ];

    let telemetry_p = Paragraph::new(telemetry_text).block(telemetry_block);
    f.render_widget(telemetry_p, chunks[2]);
}
