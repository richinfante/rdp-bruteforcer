# rdp-bruteforcer

Used as a proof of concept for testing security defenses. 

## Usage
```
Usage: rdp-bruteforcer [OPTIONS] --target <TARGET> --password-list <PASSWORD_LIST>

Options:
      --logon-domain <LOGON_DOMAIN>    Windows logon domain. Optional, default is 'domain'
      --target <TARGET>                A target IP:PORT pair
      --proxy <PROXY>                  A proxy IP:PORT pair
      --password-list <PASSWORD_LIST>  A file path on disk to use for a password source
      --username-list <USERNAME_LIST>  A file on disk as a username source (if not used, specify --username)
      --username <USERNAME>            A specific username to try (if not used, specify --username-list
  -h, --help                           Print help information
```

## Running
Clone git repo, run `cargo install`. Requires rust / cargo locally. To get started, visit https://rustup.rs/

## Disclaimer

This tool is only intented to be used in penetration tests or security demonstrations where you have *authorization from the target computer's owner*. **Do not use this tool for illegal purposes.**
