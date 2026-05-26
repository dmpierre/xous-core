//! `beth ui` — chat-style command palette for the Baochip-1x Ethereum wallet.
//!
//! Modelled after agent-harness TUIs (Claude Code, OpenCode, etc.):
//! a scrollable transcript on top, a single-line input box in the
//! middle with a slash-menu overlay, and a status bar at the bottom.
//! Slash commands mirror the CLI tree — typing `/` opens a palette
//! populated by introspecting the same `clap::Command` the CLI
//! exposes, so adding `beth foo` automatically shows up as `/foo`.
//!
//! Execution is in-process: a slash command is parsed via the same
//! `Cli::try_parse_from` the CLI uses, then routed through
//! `crate::dispatch` on a worker thread with stdout captured into the
//! transcript. One command runs at a time; the UI keeps rendering so
//! long-running commands (publish --wait, send-token --broadcast)
//! stream output line-by-line.

mod app;
mod event;
mod exec;
mod palette;
mod render;

use anyhow::{Context, Result};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::panic;
use std::time::Duration;

use app::App;
use event::{poll_event, TerminalEvent};

/// Entry point invoked from `main.rs::Commands::Ui`.
pub fn run(port: Option<&str>) -> Result<()> {
    install_panic_hook();

    enable_raw_mode().context("enable raw mode")?;
    let mut stderr = io::stderr();
    crossterm::execute!(stderr, EnterAlternateScreen, EnableBracketedPaste)
        .context("enter alt screen")?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stderr());
    let mut terminal = Terminal::new(backend).context("create Terminal")?;

    let mut app = App::new(port.map(String::from))?;

    while !app.should_quit {
        terminal.draw(|frame| render::draw(frame, &mut app))?;

        // Drain any pending command-execution messages before polling
        // for user input — keeps the transcript updated as commands
        // stream their output.
        app.drain_exec();

        match poll_event(Duration::from_millis(50))? {
            Some(TerminalEvent::Key(key)) => app.on_key(key),
            Some(TerminalEvent::Paste(s)) => app.on_paste(&s),
            Some(TerminalEvent::Resize) => { /* draw next iter */ }
            None => { /* tick; loop continues for drain + draw */ }
        }
    }

    app.save_history();
    drop(_guard);
    Ok(())
}

/// Restores the terminal on drop, even on panic. Belt-and-braces over
/// the explicit teardown.
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(io::stderr(), DisableBracketedPaste, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// Hook the global panic handler so a panic inside `draw` (or
/// anywhere downstream) doesn't leave the terminal in raw mode.
fn install_panic_hook() {
    let original = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = crossterm::execute!(io::stderr(), DisableBracketedPaste, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        original(info);
    }));
}
