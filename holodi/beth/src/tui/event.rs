//! Terminal-event polling for the TUI.

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;

pub enum TerminalEvent {
    Key(KeyEvent),
    Paste(String),
    Resize,
}

/// Poll for a terminal event with the given timeout. Returns `None`
/// on tick (no event within the timeout) so the caller can drain
/// pending command-execution messages and re-render.
pub fn poll_event(timeout: Duration) -> Result<Option<TerminalEvent>> {
    if !event::poll(timeout).context("crossterm poll")? {
        return Ok(None);
    }
    let ev = event::read().context("crossterm read")?;
    Ok(match ev {
        Event::Key(k) if k.kind == event::KeyEventKind::Press => Some(TerminalEvent::Key(k)),
        Event::Paste(s) => Some(TerminalEvent::Paste(s)),
        Event::Resize(_, _) => Some(TerminalEvent::Resize),
        // Mouse, FocusGained, FocusLost, key-release/repeat: ignore.
        _ => None,
    })
}
