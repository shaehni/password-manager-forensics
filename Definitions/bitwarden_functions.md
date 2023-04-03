# Bitwarden Module Definition
This document describes the scripts and functions available to extract relevant forensic artefacts from the Bitwarden Windows Desktop application. All functions are defined in the file `Modules/bitwarden.py`.

## Arguments for Extractor
PMF Extractor accepts the following Bitwarden-specific options:

- `--data-file`: Location of the `data.json` file.
- `--memory-dump`: Location of the memory dump file.
- `--master-pw`: If known, the master password can be manually provided to decrypt vault data.
- `--brute-force`: Text file with one password per line for brute-forcing the master password.
- `--brute-force-pin`: If the user used a PIN to unlock the vault, and disabled the option "Lock with master password on restart", the PIN can be brute-forced instead of the master password.

## Discovery
- `get_file_artefacts(data_file, Report)`: Loads the given `data.json` file, extracts the relevant forensic artefacts as defined in the pattern pre-definition file, and adds results to the report object.
- `scan_memory_for_pw(memory_dump_file):` Loads the given memory dump file and uses Yara rules in `bitwarden.yara` to scan the file for artefacts as defined in the pattern pre-definition file. Returns a string with the master password, and a list of likely vault passwords.
- `get_pbkdf_iterations(email):` If the number of PBKDF iterations could not be found in `data.json`, this fallback function will query the Bitwarden login API for the PBKDF setting for a given account email address. Returns an integer or False.

## Analysis
- `Ciphertext`: This class allows loading an encrypted vault data item from a string as it is stored in `data.json`. On instantiation, the string is split and base64 encoded fields are decoded. A Ciphertext object consists of four variables: `encryption_type`, `iv`, `data`, `mac`.
- `Decryptor`: This class can be instantiated by providing the encryption key part and the mac part of the symmetric vault key. Once instantiated, Ciphertext elements can be decrypted using the `decrypt` function. Data is validated through HMAC.

## Post-Processing
The Bitwarden module creates a report object with the chapters `Account Info`, `Cryptography`, `Vault Data`, `Password Generator`, `Memory Analysis`. All results are added to the report object during discovery and analysis. The report is created by the report objects own create function (see `pmf_scripts.md` for further information).