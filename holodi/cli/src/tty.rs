//! Terminal helpers — read a line of secret input without echoing it.
//!
//! Used by `seed import` so a pasted seed phrase doesn't show up on the
//! terminal or in scrollback. Mirrors `zao::tty::read_line_no_echo`.

use std::io::{self, BufRead, Write};

/// Read a single line from stdin without echoing characters back to the
/// terminal. Echo is restored even if the read fails or the user
/// Ctrl-Cs out (the guard's Drop handler restores termios).
///
/// Falls back to plain (echoing) line read on non-Unix or when stdin is
/// not a tty.
pub fn read_line_no_echo(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    #[cfg(unix)]
    let _guard = unix::EchoOff::new();

    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no input"))??;

    // We swallowed the user's typed Enter — emit a newline so the
    // shell prompt that follows starts on a fresh line.
    println!();
    Ok(line)
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    pub struct EchoOff {
        fd: i32,
        saved: Option<libc::termios>,
    }

    impl EchoOff {
        pub fn new() -> Self {
            let fd = io::stdin().as_raw_fd();
            let mut term = MaybeUninit::<libc::termios>::uninit();
            let saved = unsafe {
                if libc::tcgetattr(fd, term.as_mut_ptr()) == 0 {
                    let saved = term.assume_init();
                    let mut new = saved;
                    new.c_lflag &= !libc::ECHO;
                    if libc::tcsetattr(fd, libc::TCSAFLUSH, &new) == 0 {
                        Some(saved)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            Self { fd, saved }
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            if let Some(saved) = self.saved.as_ref() {
                unsafe {
                    libc::tcsetattr(self.fd, libc::TCSAFLUSH, saved);
                }
            }
        }
    }
}
