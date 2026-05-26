//! Render layer: draw the transcript, input box, optional slash-menu
//! popup, and status bar.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use super::app::{App, TranscriptLine};

/// Ethereum brand accent (the canonical "ethereum.org" violet/blue).
const ACCENT: Color = Color::Rgb(0x62, 0x7E, 0xEA);
const DIM: Color = Color::DarkGray;
const ERR: Color = Color::LightRed;

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // transcript
            Constraint::Length(3), // input box
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_transcript(frame, layout[0], app);
    draw_input(frame, layout[1], app);
    draw_status(frame, layout[2], app);

    // Slash menu popup overlays the transcript bottom + input top.
    if app.menu_selected.is_some() {
        draw_menu(frame, layout[1], app);
    }
}

fn draw_transcript(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines: Vec<Line> = app
        .transcript
        .iter()
        .flat_map(transcript_line_to_lines)
        .collect();

    // Compute scroll offset to keep the tail visible.
    let total = lines.len() as u16;
    let visible = area.height.saturating_sub(2); // borders
    let scroll = total.saturating_sub(visible);

    // Deliberately NO `.wrap(...)`. `Paragraph::wrap` reflows long
    // source lines onto multiple terminal rows, but its `.scroll((y, x))`
    // counts source lines, not rendered rows — the two disagree as
    // soon as anything wraps, and the visual symptoms are character-
    // by-character bleed-through between adjacent transcript entries.
    // Truncating long lines at the right edge keeps the scroll math
    // honest.
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DIM))
                .title(Span::styled(" beth ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))),
        )
        .scroll((scroll, 0));
    frame.render_widget(para, area);
}

fn transcript_line_to_lines(entry: &TranscriptLine) -> Vec<Line<'_>> {
    match entry {
        TranscriptLine::Input(s) => vec![Line::from(vec![
            Span::styled("› ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(s.clone(), Style::default().add_modifier(Modifier::BOLD)),
        ])],
        TranscriptLine::Output(s) => vec![Line::from(s.clone())],
        TranscriptLine::Note(s) => vec![Line::from(Span::styled(
            s.clone(),
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        ))],
        TranscriptLine::Error(s) => vec![Line::from(Span::styled(
            s.clone(),
            Style::default().fg(ERR),
        ))],
    }
}

fn draw_input(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    // tui-textarea renders the input itself; we just set the block
    // here and let it draw inside.
    let running = app.running.is_some();
    let title = if running { " running… " } else { " input " };
    let border = if running { Color::Yellow } else { DIM };

    app.input.set_block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border))
            .title(Span::styled(title, Style::default().fg(ACCENT))),
    );
    // Cursor style: invisible when a command is running.
    app.input.set_cursor_style(if running {
        Style::default()
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    });
    frame.render_widget(&app.input, area);
}

fn draw_menu(frame: &mut Frame<'_>, input_area: Rect, app: &App) {
    let entries = app.current_menu();
    if entries.is_empty() {
        return;
    }
    let selected = app.menu_selected.unwrap_or(0);

    let items: Vec<ListItem> = entries
        .iter()
        .map(|e| {
            let slash_w = e.slash.len().max(20);
            let line = Line::from(vec![
                Span::styled(
                    format!("{:width$}", e.slash, width = slash_w + 2),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(e.about.clone(), Style::default().fg(DIM)),
            ]);
            ListItem::new(line)
        })
        .collect();

    // Height: number of entries (capped) + 2 for borders.
    let max_items = 10u16;
    let height = (entries.len() as u16).min(max_items) + 2;

    // Width: longest "slash + 2 + about" line, capped at terminal width.
    let max_w = entries
        .iter()
        .map(|e| e.slash.len() + 2 + e.about.len())
        .max()
        .unwrap_or(40)
        + 2; // borders
    let width = (max_w as u16).min(input_area.width).max(40);

    // Position: just above the input box.
    let x = input_area.x;
    let y = input_area.y.saturating_sub(height);
    let rect = Rect {
        x,
        y,
        width,
        height,
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(
                    " commands ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(
            Style::default()
                .bg(ACCENT)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    state.select(Some(selected));

    frame.render_widget(Clear, rect);
    frame.render_stateful_widget(list, rect, &mut state);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        " beth ",
        Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        env!("BETH_VERSION"),
        Style::default().fg(DIM),
    ));
    // Targeted command path (the resolved subcommand the input is
    // pointing at). Shows what's about to run while the user is still
    // assembling flag values — useful when the input line scrolls or
    // when the menu is closed.
    if let Some(target) = app.target_path() {
        spans.push(Span::raw("  •  "));
        spans.push(Span::styled(
            format!("→ beth {}", target),
            Style::default().fg(ACCENT),
        ));
    }
    if let Some(port) = &app.default_port {
        spans.push(Span::raw("  •  "));
        spans.push(Span::styled(port.clone(), Style::default().fg(DIM)));
    }
    if app.running.is_some() {
        spans.push(Span::raw("  •  "));
        spans.push(Span::styled(
            "running…",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    let line = Line::from(spans);
    let para = Paragraph::new(line);
    frame.render_widget(para, area);
}
