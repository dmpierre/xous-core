//! Slash-command palette: introspects the CLI's `clap::Command` tree
//! so the menu is always in sync with the CLI surface. No manual
//! maintenance — adding a new `Commands` variant or argument in
//! `main.rs` will automatically show up here.
//!
//! Three completion modes, picked based on the current input shape:
//!   - **Command mode** — completing a (sub)command name. E.g. `/`, `/p`,
//!     `/pczt ` all show command-name suggestions.
//!   - **Flag mode** — current token starts with `-`, or we're past
//!     all the matchable subcommands and there's a trailing space.
//!     Suggestions are the `--long` flags of the resolved command.
//!   - **Empty mode** — nothing more to suggest (e.g. mid-value
//!     between a `--to <UA>` pair). Caller hides the menu.

use clap::CommandFactory;

use crate::Cli;

/// One entry in the palette.
#[derive(Clone)]
pub struct PaletteEntry {
    /// What gets put in the input when this entry is accepted.
    pub slash: String,
    /// Short help / description.
    pub about: String,
    /// True if the user is expected to keep typing after this entry
    /// is inserted (the slash gets a trailing space and the menu
    /// stays open).
    pub keep_typing: bool,
}

/// Build the palette filtered against the current input prefix.
pub fn entries_for(input: &str) -> Vec<PaletteEntry> {
    let body = input.trim_start_matches('/');
    let parts: Vec<&str> = body.split_whitespace().collect();
    let trailing_space = body.is_empty() || body.ends_with(' ');

    let root = Cli::command();

    // Walk the (sub)command path: consume non-`-` parts that match a
    // subcommand. Stop at the first part that's a flag (`--foo`) or
    // doesn't match.
    let mut cmd: &clap::Command = &root;
    let mut path: Vec<String> = Vec::new();
    let mut consumed: usize = 0;
    for p in &parts {
        if p.starts_with('-') {
            break;
        }
        let Some(s) = cmd.find_subcommand(p) else {
            break;
        };
        cmd = s;
        path.push((*p).to_string());
        consumed += 1;
    }

    let path_str = if path.is_empty() {
        String::new()
    } else {
        format!("/{}", path.join(" "))
    };
    let remaining: &[&str] = &parts[consumed..];
    let last_partial: Option<&str> = if trailing_space {
        None
    } else {
        remaining.last().copied()
    };
    let at_root = path.is_empty();

    // Flags already typed in this command — used to filter them out of
    // the menu (we don't want to suggest `--to` if the user already
    // typed `--to u1…`).
    let taken_flags: Vec<&str> = remaining
        .iter()
        .filter(|p| p.starts_with("--"))
        .copied()
        .collect();

    // ----- Decide which suggestion list applies. -----

    // Case A: user is mid-typing a token that looks like a flag.
    if let Some(partial) = last_partial {
        if partial.starts_with('-') {
            // When filtering "already taken", don't filter the partial
            // we're currently completing.
            let mut taken: Vec<&str> = taken_flags.clone();
            taken.retain(|f| *f != partial);
            return flag_entries(cmd, &path_str, partial, &taken);
        }
    }

    // Case B: user is mid-typing a subcommand name. We have exactly
    // one trailing non-flag partial and the resolved command still
    // has subcommands to offer.
    if let Some(partial) = last_partial {
        if !partial.starts_with('-') && cmd.has_subcommands() {
            return subcmd_entries(cmd, &path_str, partial, at_root);
        }
    }

    // Case C: trailing space. Show whichever is more useful — if the
    // command still has subcommands and no flags have been typed yet,
    // suggest subcommands; otherwise suggest flags.
    if trailing_space {
        let any_flag_seen = !taken_flags.is_empty();
        if cmd.has_subcommands() && !any_flag_seen {
            return subcmd_entries(cmd, &path_str, "", at_root);
        }
        return flag_entries(cmd, &path_str, "", &taken_flags);
    }

    Vec::new()
}

/// Resolved subcommand path for the current input (no leading `/`,
/// space-separated). Used by the status bar.
pub fn target_path(input: &str) -> String {
    let body = input.trim_start_matches('/');
    let parts: Vec<&str> = body.split_whitespace().collect();
    let root = Cli::command();
    let mut cmd: &clap::Command = &root;
    let mut path: Vec<String> = Vec::new();
    for p in &parts {
        if p.starts_with('-') {
            break;
        }
        let Some(s) = cmd.find_subcommand(p) else {
            break;
        };
        cmd = s;
        path.push((*p).to_string());
    }
    path.join(" ")
}

/// List `cmd`'s subcommands filtered by prefix. `path_prefix` is the
/// slash-form of the already-typed path (`""` at root, `"/pczt"` etc.).
fn subcmd_entries(
    cmd: &clap::Command,
    path_prefix: &str,
    prefix: &str,
    at_root: bool,
) -> Vec<PaletteEntry> {
    let mut out: Vec<PaletteEntry> = Vec::new();
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        if !name.starts_with(prefix) {
            continue;
        }
        if at_root && name == "ui" {
            // Calling `/ui` from inside the TUI would recurse. Skip.
            continue;
        }
        let slash = if path_prefix.is_empty() {
            format!("/{}", name)
        } else {
            format!("{} {}", path_prefix, name)
        };
        out.push(PaletteEntry {
            slash,
            about: short_about(sub),
            keep_typing: sub.has_subcommands() || sub_takes_args(sub),
        });
    }
    out.sort_by(|a, b| a.slash.cmp(&b.slash));
    if at_root {
        out.extend(builtin_entries(prefix));
    }
    out
}

/// List `cmd`'s `--long` flags filtered by prefix, excluding flags
/// the user has already typed (`taken_flags`, each in `--long` form).
/// `path_prefix` is the slash-form already typed (e.g. `"/pczt propose"`).
fn flag_entries(
    cmd: &clap::Command,
    path_prefix: &str,
    prefix: &str,
    taken_flags: &[&str],
) -> Vec<PaletteEntry> {
    let mut out: Vec<PaletteEntry> = Vec::new();
    let normalized_prefix = if prefix.is_empty() {
        "--"
    } else if prefix == "-" {
        "-"
    } else {
        prefix
    };
    for arg in cmd.get_arguments() {
        // Skip auto-added help/version.
        let id = arg.get_id().as_str();
        if id == "help" || id == "version" {
            continue;
        }
        let Some(long) = arg.get_long() else { continue };
        let flag = format!("--{}", long);
        if !flag.starts_with(normalized_prefix) {
            continue;
        }
        // Skip flags the user already provided — keeps the menu focused
        // on what's still to be typed.
        if taken_flags.iter().any(|t| *t == flag.as_str()) {
            continue;
        }
        // Most zao flags take a value (long takes_value); only a few
        // are bool toggles. clap's `get_action()` tells us:
        let takes_value = !matches!(
            arg.get_action(),
            clap::ArgAction::SetTrue
                | clap::ArgAction::SetFalse
                | clap::ArgAction::Count
                | clap::ArgAction::Help
                | clap::ArgAction::Version
        );

        // Compose slash from the existing path + flag.
        let slash = format!("{} {}", path_prefix, flag);
        let about = arg_help(arg);
        // Mark required flags so the user can prioritise.
        let about = if arg.is_required_set() {
            format!("(required) {}", about)
        } else {
            about
        };
        out.push(PaletteEntry {
            slash,
            about,
            keep_typing: takes_value, // need to provide the value next
        });
    }
    out.sort_by(|a, b| a.slash.cmp(&b.slash));
    out
}

/// First line of a clap (sub)command's about/long-about text.
fn short_about(cmd: &clap::Command) -> String {
    cmd.get_about()
        .or_else(|| cmd.get_long_about())
        .map(|s| {
            let s = s.to_string();
            s.lines().next().unwrap_or("").trim().to_string()
        })
        .unwrap_or_default()
}

/// First line of a clap arg's help text.
fn arg_help(arg: &clap::Arg) -> String {
    arg.get_help()
        .or_else(|| arg.get_long_help())
        .map(|s| {
            let s = s.to_string();
            s.lines().next().unwrap_or("").trim().to_string()
        })
        .unwrap_or_default()
}

/// Does this clap command accept any non-global positional / named args
/// (beyond `--help`, `--version`)? Used to set `keep_typing` correctly
/// on the subcommand entry (so Enter leaves a trailing space if the
/// user will need to provide flags).
fn sub_takes_args(cmd: &clap::Command) -> bool {
    cmd.get_arguments().any(|a| {
        let id = a.get_id().as_str();
        id != "help" && id != "version" && !a.is_global_set()
    })
}

/// TUI-only commands (not part of the CLI). Filtered against the
/// same prefix the user is typing.
fn builtin_entries(prefix: &str) -> Vec<PaletteEntry> {
    let candidates: &[(&str, &str)] = &[
        ("quit", "Exit the TUI"),
        ("clear", "Clear the transcript"),
        ("help", "Show TUI-specific help"),
    ];
    candidates
        .iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(name, about)| PaletteEntry {
            slash: format!("/{}", name),
            about: (*about).to_string(),
            keep_typing: false,
        })
        .collect()
}
