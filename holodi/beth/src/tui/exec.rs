//! In-process command execution for the TUI.
//!
//! Runs the same `crate::dispatch` the CLI uses on a worker thread,
//! with process stdout redirected to a pipe via raw `libc` so we get
//! true streaming. A reader thread pulls lines off the pipe and
//! forwards each one back to the UI through a `Sender<ExecMsg>` so
//! the transcript updates as a command produces output rather than
//! waiting for completion.
//!
//! Unix-only — matches the rest of the wallet tooling on this branch.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use clap::Parser;

use crate::{dispatch, Cli};

/// Streaming message from a running command back to the UI.
pub enum ExecMsg {
    /// One line of stdout from the running command.
    Line(String),
    /// Command finished. `Ok(())` on success; `Err(msg)` on failure.
    /// Always the last message a handle yields.
    Done(Result<(), String>),
}

/// Outcome of `spawn` before the command actually runs.
pub enum SpawnError {
    /// Clap's `--help` / `--version` / "display help on missing args"
    /// path. The text is the rendered help/version block, which should
    /// surface in the transcript as informational output, not as an
    /// error (it's not really an error — the user asked for help).
    Help(String),
    /// Real parse / refusal error (missing required arg, unknown
    /// subcommand, refused interactive command, etc.). Renders as Error
    /// in the transcript.
    Fail(String),
}

/// Handle to a running (or completed) in-process command.
pub struct ExecHandle {
    pub rx: Receiver<ExecMsg>,
}

impl ExecHandle {
    /// Drain pending messages without blocking. Returns the new lines
    /// and an optional final outcome if the command completed.
    pub fn drain(&self) -> (Vec<String>, Option<Result<(), String>>) {
        let mut lines = Vec::new();
        let mut done: Option<Result<(), String>> = None;
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                ExecMsg::Line(s) => lines.push(s),
                ExecMsg::Done(r) => {
                    done = Some(r);
                    break;
                }
            }
        }
        (lines, done)
    }
}

/// Parse a slash-form input and spawn it on a worker thread.
///
/// `input` is the user-typed line *without* the leading `/`, e.g.
/// `"address --index 0"` or `"send-token --token 0xA0… …"`.
///
/// `default_port` comes from the `beth ui` invocation's own `--port`
/// flag; the slash command can override it inline.
pub fn spawn(input: &str, default_port: Option<&str>) -> Result<ExecHandle, SpawnError> {
    // Build argv: ["beth", <space-split user input>].
    let mut argv: Vec<String> = vec!["beth".to_string()];
    argv.extend(input.split_whitespace().map(|s| s.to_string()));

    let cli = match Cli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            return Err(match e.kind() {
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                | ErrorKind::DisplayVersion => SpawnError::Help(format!("{}", e)),
                _ => SpawnError::Fail(format!("{}", e)),
            });
        }
    };

    // Guard against recursion: launching the TUI from inside itself
    // would re-enter `run()` on the dispatch worker thread and
    // hijack the terminal.
    if matches!(cli.command, crate::Commands::Ui) {
        return Err(SpawnError::Fail(
            "'/ui' is not allowed from inside the TUI".to_string(),
        ));
    }

    // Refuse commands that read from stdin interactively. The TUI
    // owns stdin in raw mode + alt-screen; the command's blocking
    // `read_line` deadlocks against our event loop. The CLI remains
    // the home for these — run them from a regular shell.
    let interactive_label = match &cli.command {
        crate::Commands::ImportEncrypted => Some("/import-encrypted"),
        crate::Commands::DangerousMode => Some("/dangerous-mode"),
        _ => None,
    };
    if let Some(label) = interactive_label {
        return Err(SpawnError::Fail(format!(
            "'{}' is interactive (reads stdin) and isn't supported from the TUI yet. \
             Exit the TUI (Ctrl-D) and run the equivalent `beth …` command directly.",
            label
        )));
    }

    let port = cli.port.clone().or_else(|| default_port.map(String::from));
    let command = cli.command;

    let (tx, rx) = channel::<ExecMsg>();

    thread::spawn(move || run_dispatch(command, port, tx));

    Ok(ExecHandle { rx })
}

/// Worker-thread body: redirect stdout AND stderr to the same pipe,
/// run dispatch, stream captured lines via the channel, restore both
/// fds, signal Done.
///
/// Stderr is captured because some commands (`dangerous-mode` warning,
/// occasional eprintln!) write straight to stderr — without redirecting
/// it, their output writes underneath the TUI's alt-screen and visibly
/// corrupts rendering. Both fds share one pipe so the reader sees a
/// merged ordered stream (still chronological per-write).
fn run_dispatch(command: crate::Commands, port: Option<String>, tx: Sender<ExecMsg>) {
    // Save originals so we can restore after the command.
    let saved_stdout: i32 = unsafe { libc::dup(libc::STDOUT_FILENO) };
    let saved_stderr: i32 = unsafe { libc::dup(libc::STDERR_FILENO) };
    if saved_stdout < 0 || saved_stderr < 0 {
        let err = io::Error::last_os_error();
        if saved_stdout >= 0 {
            unsafe { libc::close(saved_stdout) };
        }
        if saved_stderr >= 0 {
            unsafe { libc::close(saved_stderr) };
        }
        let _ = tx.send(ExecMsg::Done(Err(format!("dup failed: {}", err))));
        return;
    }

    // Create a single pipe; route both stdout and stderr into its
    // write end.
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 {
        unsafe {
            libc::close(saved_stdout);
            libc::close(saved_stderr);
        }
        let _ = tx.send(ExecMsg::Done(Err(format!(
            "pipe failed: {}",
            io::Error::last_os_error()
        ))));
        return;
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    if unsafe { libc::dup2(write_fd, libc::STDOUT_FILENO) } < 0
        || unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) } < 0
    {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
            libc::dup2(saved_stdout, libc::STDOUT_FILENO);
            libc::dup2(saved_stderr, libc::STDERR_FILENO);
            libc::close(saved_stdout);
            libc::close(saved_stderr);
        }
        let _ = tx.send(ExecMsg::Done(Err(format!(
            "dup2 failed: {}",
            io::Error::last_os_error()
        ))));
        return;
    }
    // FDs 1 and 2 now hold the only refs to the pipe write end; we
    // can close the original write_fd descriptor. The pipe stays open
    // as long as one of FD 1 or FD 2 points at it.
    unsafe { libc::close(write_fd) };

    // Spawn the reader BEFORE dispatch so the pipe drains in real
    // time. Otherwise the pipe buffer (typically 64 KiB) would fill
    // up and dispatch would block on its next write.
    let reader_tx = tx.clone();
    let reader_handle = thread::spawn(move || {
        // SAFETY: read_fd is a fresh fd from `pipe()`, owned exclusively
        // here. The File owns it; we don't dup it.
        let read_file = unsafe { File::from_raw_fd(read_fd) };
        let reader = BufReader::new(read_file);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    let cleaned = strip_ansi(&l);
                    if reader_tx.send(ExecMsg::Line(cleaned)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Run the command. Any println!/print!/eprintln! from dispatch
    // lands in the pipe; the reader thread forwards each line to UI.
    let outcome = dispatch(command, port.as_deref()).map_err(|e| format!("{:#}", e));

    // Flush both streams before restoring fds so nothing is lost.
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    // Restore originals. This closes both refs to the pipe write end,
    // so the reader sees EOF and exits.
    unsafe {
        libc::dup2(saved_stdout, libc::STDOUT_FILENO);
        libc::dup2(saved_stderr, libc::STDERR_FILENO);
        libc::close(saved_stdout);
        libc::close(saved_stderr);
    }

    // Wait for the reader to drain any final buffered lines.
    let _ = reader_handle.join();

    let _ = tx.send(ExecMsg::Done(outcome));
}

/// Strip ANSI escape sequences from a line. Some command output (e.g.
/// from underlying crates) may include `\x1b[…m` colour codes that
/// would otherwise render as raw escape garbage in the transcript.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        // ESC found. Most common case: CSI sequence `\x1b[...<final>`
        // where the final byte is in 0x40..=0x7E.
        match chars.peek() {
            Some('[') => {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if matches!(next, '\x40'..='\x7E') {
                        break;
                    }
                }
            }
            Some(']') => {
                // OSC: `\x1b]...\x07` or `\x1b]...\x1b\\`. Skip until BEL
                // or ESC-backslash; bail at EOL to be safe.
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next == '\x07' {
                        break;
                    }
                }
            }
            Some(_) => {
                // Other simple escapes: skip the next byte.
                chars.next();
            }
            None => break,
        }
    }
    out
}
