# cma-Credential-Sanitizer
Removes secrets from command history files (bash, zsh, powershell) and Jupyter Notebooks. Identifies and redacts API keys, passwords, and other credentials using regular expressions, backing up original files before modification.  Uses `os` for file system access, `re` for regex, and potentially `shutil` for backups. - Focused on Automates the rotation, storage, and injection of credentials into various applications and systems.  Manages API keys, passwords, and other sensitive information, leveraging secure vaults and time-based token generation to minimize the risk of credential compromise.

## Install
`git clone https://github.com/ShadowGuardAI/cma-credential-sanitizer`

## Usage
`./cma-credential-sanitizer [params]`

## Parameters
- `-h`: Show help message and exit
- `--filetype`: No description provided
- `--filepath`: The specific file path to sanitize.  Overrides --filetype if provided.
- `--directory`: No description provided
- `--all`: No description provided
- `--regex_file`: No description provided

## License
Copyright (c) ShadowGuardAI
