use ratatui::style::{Color, Modifier, Style};

pub struct Theme;

impl Theme {
    // Brand & Accent Colors
    pub const ACCENT: Color = Color::Rgb(0, 212, 255); // Electric Cyan
    pub const ACCENT_SECONDARY: Color = Color::Rgb(168, 85, 247); // Purple / Violet
    pub const BG_DARK: Color = Color::Rgb(15, 18, 28); // Deep Slate
    pub const BG_PANEL: Color = Color::Rgb(22, 27, 42); // Slate Card
    pub const BORDER_NORMAL: Color = Color::Rgb(55, 65, 81); // Dim Gray Border
    pub const BORDER_FOCUS: Color = Color::Rgb(0, 212, 255); // Cyan Focus Border
    pub const BORDER_SIDEBAR: Color = Color::Rgb(79, 70, 229); // Indigo Sidebar Border

    // Status Colors
    pub const SUCCESS: Color = Color::Rgb(34, 197, 94); // Emerald Green
    pub const WARNING: Color = Color::Rgb(245, 158, 11); // Amber / Gold
    pub const DANGER: Color = Color::Rgb(239, 68, 68); // Crimson Red
    pub const INFO: Color = Color::Rgb(59, 130, 246); // Blue
    pub const MUTED: Color = Color::Rgb(156, 163, 175); // Light Gray

    // Text & Element Styles
    pub fn title() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn subtitle() -> Style {
        Style::default()
            .fg(Self::ACCENT_SECONDARY)
            .add_modifier(Modifier::BOLD)
    }

    pub fn normal() -> Style {
        Style::default().fg(Color::Rgb(243, 244, 246))
    }

    pub fn muted() -> Style {
        Style::default().fg(Self::MUTED)
    }

    pub fn success() -> Style {
        Style::default()
            .fg(Self::SUCCESS)
            .add_modifier(Modifier::BOLD)
    }

    pub fn warning() -> Style {
        Style::default()
            .fg(Self::WARNING)
            .add_modifier(Modifier::BOLD)
    }

    pub fn danger() -> Style {
        Style::default()
            .fg(Self::DANGER)
            .add_modifier(Modifier::BOLD)
    }

    pub fn selected_row() -> Style {
        Style::default()
            .bg(Color::Rgb(30, 41, 59))
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn sidebar_active() -> Style {
        Style::default()
            .bg(Color::Rgb(49, 46, 129))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    }

    pub fn sidebar_inactive() -> Style {
        Style::default().fg(Color::Rgb(199, 210, 254))
    }

    pub fn table_header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .bg(Color::Rgb(17, 24, 39))
            .add_modifier(Modifier::BOLD)
    }

    pub fn shortcut_key() -> Style {
        Style::default()
            .fg(Self::WARNING)
            .add_modifier(Modifier::BOLD)
    }
}
