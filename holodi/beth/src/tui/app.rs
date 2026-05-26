//! App state for the TUI.

use std::path::PathBuf;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tui_textarea::TextArea;

use super::exec::{spawn, ExecHandle, SpawnError};
use super::palette::{entries_for, target_path, PaletteEntry};

/// One row in the transcript.
pub enum TranscriptLine {
    /// User-entered command, echoed with a `›` prompt.
    Input(String),
    /// Captured stdout from a running command.
    Output(String),
    /// Local notice (info, error, status). Rendered dim/coloured.
    Note(String),
    /// Error from command parse or execution. Rendered red.
    Error(String),
}

pub struct App {
    pub should_quit: bool,
    pub transcript: Vec<TranscriptLine>,
    pub input: TextArea<'static>,
    /// Optional currently-running command. While `Some`, the input
    /// area is read-only and a spinner shows in the status line.
    pub running: Option<ExecHandle>,

    /// Slash-menu state. `Some(idx)` means visible with `idx`-th entry
    /// highlighted. `None` means hidden.
    pub menu_selected: Option<usize>,

    /// Default inherited from the `beth ui` invocation; slash commands
    /// can override on a per-call basis.
    pub default_port: Option<String>,

    /// Input history — Up/Down on an empty / non-edited input cycles
    /// through. Persisted to `history_path` on save.
    pub history: Vec<String>,
    pub history_cursor: Option<usize>,
    history_path: Option<PathBuf>,
}

impl App {
    pub fn new(port: Option<String>) -> Result<Self> {
        let mut input = TextArea::default();
        input.set_cursor_line_style(ratatui::style::Style::default());
        input.set_placeholder_text("Type a command, or '/' for the menu");

        let history_path = dirs_next::data_local_dir()
            .map(|d| d.join("beth").join("tui_history"))
            .or_else(|| dirs_next::home_dir().map(|h| h.join(".beth").join("tui_history")));
        let history = history_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();

        let mut app = App {
            should_quit: false,
            transcript: Vec::new(),
            input,
            running: None,
            menu_selected: None,
            default_port: port,
            history,
            history_cursor: None,
            history_path,
        };
        app.welcome();
        Ok(app)
    }

    fn welcome(&mut self) {
        self.transcript.push(TranscriptLine::Note(format!(
            "beth {} — type '/' for commands, Ctrl-D to exit",
            env!("BETH_VERSION")
        )));
    }

    pub fn save_history(&self) {
        let Some(path) = &self.history_path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Last 200 entries.
        let start = self.history.len().saturating_sub(200);
        let body = self.history[start..].join("\n");
        let _ = std::fs::write(path, body);
    }

    /// Drain any pending stdout-stream / completion messages from a
    /// running command. Called every frame.
    pub fn drain_exec(&mut self) {
        let Some(handle) = &self.running else { return };
        let (lines, done) = handle.drain();
        for l in lines {
            self.transcript.push(TranscriptLine::Output(l));
        }
        if let Some(r) = done {
            match r {
                Ok(()) => {
                    self.transcript
                        .push(TranscriptLine::Note("[done]".to_string()));
                }
                Err(e) => {
                    // Multi-line errors are pretty common (clap usage,
                    // anyhow chains). Render each line separately.
                    for line in e.lines() {
                        self.transcript.push(TranscriptLine::Error(line.to_string()));
                    }
                }
            }
            self.running = None;
        }
    }

    /// Current input text as a single trimmed line. The TextArea is
    /// single-line for now so we just take `lines()[0]`.
    pub fn input_text(&self) -> &str {
        self.input.lines().first().map(|s| s.as_str()).unwrap_or("")
    }

    fn set_input(&mut self, s: &str) {
        self.input.select_all();
        self.input.cut(); // clears
        self.input.insert_str(s);
    }

    fn clear_input(&mut self) {
        self.input.select_all();
        self.input.cut();
    }

    pub fn on_paste(&mut self, s: &str) {
        if self.running.is_some() {
            return;
        }
        // Strip newlines — single-line input only. Replace tabs with
        // a space too.
        let cleaned: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
        self.input.insert_str(&cleaned);
        self.refresh_menu();
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        // Ctrl-D / Ctrl-C: exit (even while a command runs — gives
        // the user an escape valve; the running command continues
        // until it finishes, but we set the quit flag).
        if matches!(key.code, KeyCode::Char('d') | KeyCode::Char('c'))
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            // Ctrl-C while command is running cancels by sending
            // SIGINT-equivalent: we can't actually cancel an
            // in-process call cleanly, so just note it.
            if self.running.is_some() && key.code == KeyCode::Char('c') {
                self.transcript.push(TranscriptLine::Note(
                    "[Ctrl-C: cancel during in-process commands not supported; will exit after current command]".to_string(),
                ));
            }
            self.should_quit = true;
            return;
        }

        // Ctrl-L: clear transcript.
        if key.code == KeyCode::Char('l') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.transcript.clear();
            return;
        }

        // Block most input while a command runs.
        if self.running.is_some() {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                if self.menu_selected.is_some() {
                    self.menu_selected = None;
                } else if self.input_text().is_empty() {
                    self.should_quit = true;
                } else {
                    self.clear_input();
                }
            }
            KeyCode::Enter => self.on_enter(),
            KeyCode::Tab => self.on_tab(),
            KeyCode::Up => self.on_up(),
            KeyCode::Down => self.on_down(),
            _ => {
                // Forward to the TextArea's key handler. tui-textarea
                // accepts a crossterm KeyEvent directly via its
                // `From<KeyEvent> for Input` impl.
                self.input.input(key);
                self.history_cursor = None;
                self.refresh_menu();
            }
        }
    }

    fn refresh_menu(&mut self) {
        let text = self.input_text();
        if text.starts_with('/') {
            let entries = entries_for(text);
            if entries.is_empty() {
                self.menu_selected = None;
            } else {
                // Keep selection if still in range, else reset to 0.
                let idx = self.menu_selected.unwrap_or(0).min(entries.len() - 1);
                self.menu_selected = Some(idx);
            }
        } else {
            self.menu_selected = None;
        }
    }

    /// Current palette snapshot for rendering / Enter / Tab handling.
    pub fn current_menu(&self) -> Vec<PaletteEntry> {
        let text = self.input_text();
        if self.menu_selected.is_none() || !text.starts_with('/') {
            return Vec::new();
        }
        entries_for(text)
    }

    fn on_tab(&mut self) {
        // If menu is closed and the input is in a state where we *could*
        // suggest something, force-open the menu. This is the
        // "Tab re-opens completion" behaviour the CLI gets from
        // bash/zsh.
        if self.menu_selected.is_none() {
            let text = self.input_text();
            if text.is_empty() {
                // Empty input → prefix with `/` so the palette opens at
                // top level. Power-user shortcut: bare Tab on empty
                // input gets you the command list.
                self.set_input("/");
            }
            if self.input_text().starts_with('/') {
                self.refresh_menu();
            }
            return;
        }

        // Menu open: accept the highlighted entry.
        let menu = self.current_menu();
        let Some(idx) = self.menu_selected else { return };
        if let Some(entry) = menu.get(idx) {
            let mut s = entry.slash.clone();
            if entry.keep_typing {
                s.push(' ');
            }
            self.set_input(&s);
            self.refresh_menu();
        }
    }

    fn on_up(&mut self) {
        if self.menu_selected.is_some() {
            let menu_len = self.current_menu().len();
            let idx = self.menu_selected.unwrap();
            self.menu_selected = Some(if idx == 0 { menu_len.saturating_sub(1) } else { idx - 1 });
            return;
        }
        // History: cycle backwards.
        if self.history.is_empty() {
            return;
        }
        let next = match self.history_cursor {
            None => self.history.len() - 1,
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_cursor = Some(next);
        let s = self.history[next].clone();
        self.set_input(&s);
    }

    fn on_down(&mut self) {
        if self.menu_selected.is_some() {
            let menu_len = self.current_menu().len();
            if menu_len == 0 {
                return;
            }
            let idx = self.menu_selected.unwrap();
            self.menu_selected = Some((idx + 1) % menu_len);
            return;
        }
        if let Some(c) = self.history_cursor {
            if c + 1 >= self.history.len() {
                self.history_cursor = None;
                self.clear_input();
            } else {
                self.history_cursor = Some(c + 1);
                let s = self.history[c + 1].clone();
                self.set_input(&s);
            }
        }
    }

    fn on_enter(&mut self) {
        // If the menu is open with a non-leaf entry highlighted, Enter
        // completes; otherwise (or for leaves) it submits.
        let menu = self.current_menu();
        if let Some(idx) = self.menu_selected {
            if let Some(entry) = menu.get(idx) {
                if entry.keep_typing {
                    let mut s = entry.slash.clone();
                    s.push(' ');
                    self.set_input(&s);
                    self.refresh_menu();
                    return;
                } else if entry.slash != format!("/{}", self.input_text().trim_start_matches('/')) {
                    // Highlighted entry differs from typed text: complete it.
                    self.set_input(&entry.slash);
                    self.refresh_menu();
                    return;
                }
                // Otherwise fall through and submit.
            }
        }
        self.submit();
    }

    fn submit(&mut self) {
        let text = self.input_text().trim().to_string();
        if text.is_empty() {
            return;
        }

        // Echo input.
        self.transcript.push(TranscriptLine::Input(text.clone()));

        // History push (de-duplicate consecutive).
        if self.history.last() != Some(&text) {
            self.history.push(text.clone());
        }
        self.history_cursor = None;
        self.clear_input();
        self.menu_selected = None;

        // Built-in TUI commands.
        if let Some(stripped) = text.strip_prefix('/') {
            let head = stripped.split_whitespace().next().unwrap_or("");
            match head {
                "quit" | "exit" => {
                    self.should_quit = true;
                    return;
                }
                "clear" => {
                    self.transcript.clear();
                    return;
                }
                "help" => {
                    self.show_tui_help();
                    return;
                }
                _ => {}
            }
            self.spawn_command(stripped);
        } else {
            // Bare text without `/` — treat as if the user typed it
            // and remind them.
            self.transcript.push(TranscriptLine::Note(
                "Hint: prefix commands with '/'. E.g. '/address --index 0'".to_string(),
            ));
        }
    }

    fn spawn_command(&mut self, body: &str) {
        match spawn(body, self.default_port.as_deref()) {
            Ok(handle) => {
                self.running = Some(handle);
            }
            Err(SpawnError::Help(text)) => {
                // `--help` / `--version` aren't errors — render the
                // text dim and skip blank rows so the help block
                // sits clean in the transcript.
                let mut last_blank = false;
                for line in text.lines() {
                    let blank = line.trim().is_empty();
                    if blank && last_blank {
                        continue;
                    }
                    if !blank {
                        self.transcript.push(TranscriptLine::Note(line.to_string()));
                    }
                    last_blank = blank;
                }
            }
            Err(SpawnError::Fail(text)) => {
                // clap parse errors include blank-line separators
                // between "error:", "Usage:", and the "For more info"
                // hint; collapse them for a tight error block.
                let mut last_blank = false;
                for line in text.lines() {
                    let blank = line.trim().is_empty();
                    if blank && last_blank {
                        continue;
                    }
                    if !blank {
                        self.transcript.push(TranscriptLine::Error(line.to_string()));
                    }
                    last_blank = blank;
                }
            }
        }
    }

    /// Resolved subcommand path for the current input — used by the
    /// status bar to show what command the user is targeting (e.g.
    /// `send-token` while they're typing flag values).
    pub fn target_path(&self) -> Option<String> {
        let text = self.input_text();
        if !text.starts_with('/') {
            return None;
        }
        let p = target_path(text);
        if p.is_empty() {
            None
        } else {
            Some(p)
        }
    }

    fn show_tui_help(&mut self) {
        let lines = [
            "TUI quick reference:",
            "  /              open command menu",
            "  /<prefix>      filter top-level commands",
            "  /address <Tab> complete the highlighted entry",
            "  Tab            complete highlighted menu entry",
            "  Enter          execute current input (or complete if menu open)",
            "  ↑ / ↓          cycle history (or menu when open)",
            "  Esc            close menu / clear input / exit on empty",
            "  Ctrl-L         clear transcript",
            "  Ctrl-D         exit",
            "Built-in commands: /quit /clear /help",
            "All other commands match the CLI subcommands shown by 'beth --help'.",
        ];
        for line in lines {
            self.transcript.push(TranscriptLine::Note(line.to_string()));
        }
    }
}
