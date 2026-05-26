use String;

use crate::{CommonEnv, ShellCmdApi};
use bao_seed_api::{BaoSeedClient, MnemonicWords};

pub struct Seed {
    client: Option<BaoSeedClient>,
}

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Seed").field("connected", &self.client.is_some()).finish()
    }
}

impl Seed {
    pub fn new() -> Self { Seed { client: None } }

    fn client(&mut self) -> Result<&BaoSeedClient, xous::Error> {
        if self.client.is_none() {
            match BaoSeedClient::new() {
                Ok(c) => self.client = Some(c),
                Err(e) => {
                    log::error!("seed: failed to connect to bao-seed: {:?}", e);
                    return Err(xous::Error::InternalError);
                }
            }
        }
        Ok(self.client.as_ref().unwrap())
    }
}

impl<'a> ShellCmdApi<'a> for Seed {
    cmd_api!(seed);

    fn process(&mut self, args: String, _env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        use core::fmt::Write;
        let mut ret = String::new();

        let helpstring = "seed [status|hasseed|generate [12|24]|import <w1 w2 … wN on one line>|wipe]";

        let mut parts = args.split_whitespace();
        let cmd = parts.next().unwrap_or("").to_string();
        let rest: Vec<String> = parts.map(|s| s.to_string()).collect();

        match cmd.as_str() {
            "status" => {
                let client = self.client()?;
                match client.status() {
                    Ok(s) => {
                        write!(
                            ret,
                            "protocol_version={} has_seed={} fingerprint=",
                            s.protocol_version,
                            s.has_seed,
                        )
                        .ok();
                        match s.fingerprint {
                            Some(fp) => {
                                for b in &fp {
                                    write!(ret, "{:02x}", b).ok();
                                }
                            }
                            None => {
                                write!(ret, "(none)").ok();
                            }
                        }
                    }
                    Err(e) => write!(ret, "status failed: {:?}", e).unwrap(),
                }
            }

            "hasseed" | "has-seed" => {
                let client = self.client()?;
                match client.has_seed() {
                    Ok(true) => write!(ret, "true").unwrap(),
                    Ok(false) => write!(ret, "false").unwrap(),
                    Err(e) => write!(ret, "has-seed failed: {:?}", e).unwrap(),
                }
            }

            "generate" => {
                let word_count: u8 = rest
                    .first()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(24);
                let client = self.client()?;
                match client.generate(word_count) {
                    Ok(resp) => {
                        write!(ret, "fingerprint=").ok();
                        for b in &resp.fingerprint {
                            write!(ret, "{:02x}", b).ok();
                        }
                        write!(ret, " words=").ok();
                        for (i, w) in resp.words.as_slice().iter().enumerate() {
                            if i > 0 {
                                write!(ret, " ").ok();
                            }
                            write!(ret, "{}", w).ok();
                        }
                    }
                    Err(e) => write!(ret, "generate failed: {:?}", e).unwrap(),
                }
            }

            "import" => {
                if rest.is_empty() {
                    write!(
                        ret,
                        "usage: seed import <w1> <w2> ... <wN>\n\
                         all 12/15/18/21/24 words on the SAME line, space-separated\n\
                         example: seed import abandon abandon abandon ... about",
                    )
                    .unwrap();
                } else {
                    match MnemonicWords::new(rest.clone()) {
                        Ok(words) => {
                            let client = self.client()?;
                            match client.import(words) {
                                Ok(resp) => {
                                    write!(ret, "fingerprint=").ok();
                                    for b in &resp.fingerprint {
                                        write!(ret, "{:02x}", b).ok();
                                    }
                                }
                                Err(e) => write!(ret, "import failed: {:?}", e).unwrap(),
                            }
                        }
                        Err(e) => write!(ret, "invalid mnemonic length: {:?}", e).unwrap(),
                    }
                }
            }

            "wipe" => {
                let client = self.client()?;
                match client.wipe() {
                    Ok(()) => write!(ret, "wiped").unwrap(),
                    Err(e) => write!(ret, "wipe failed: {:?}", e).unwrap(),
                }
            }

            "" => write!(ret, "{}", helpstring).unwrap(),
            _ => write!(ret, "unknown: {}\n{}", cmd, helpstring).unwrap(),
        }

        Ok(Some(ret))
    }
}
