# KeePass Module Definition
This document describes the scripts and functions available to extract relevant forensic artefacts from the KeePass Windows Desktop application. All functions are defined in the file `Modules/keepass.py`.

## Arguments for Extractor
PMF Extractor accepts the following Bitwarden-specific options:

- `--database`: Location of the KeePass database file (`.kdbx`).
- `--memory-dump`: Location of the memory dump file.
- `--config-file`: Location of the KeePass configuration file (`KeePass.config.xml`)
- `--master-pw`: If known, the master password can be manually provided to decrypt vault data.
- `--key-file`: Location of the key file that is part of the master key.
- `--brute-force`: Text file with one password per line for brute-forcing.

## Discovery
- `get_database_info(database_file, Report)`: Reads the (binary) header data from a KeePass database file and extracts relevant information (File version, Master seed, Transform seed and rounds, Initialisation vector)
- `parse_config_file(config_file, Report)`: Parses the KeePass configuration file and extracts relevant information (last used databases and their encryption configuration).
- `scan_memory_for_pw(memory_dump_file):` Loads the given memory dump file and uses Yara rules in `keepass.yara` to scan the file for artefacts as defined in the pattern pre-definition file. Returns a tuple containing a list of possible master passwords, and a list of likely vault passwords.

## Analysis
- `pykeepass`: PMF uses the external module python module [pykeepass][1] to decrypt the database file and to export vault items. First, a `PyKeePass` object is created by providing necessary decryption information. Then, by iterating over all vault items, vault data is extracted and sent to the reporter module.

[1]: https://github.com/libkeepass/pykeepass

## Post-Processing
The KeePass module creates a report object with the chapters `Database`, `Cryptography`, `Vault Data`, `Password Generator`, `Memory Analysis`. All results are added to the report object during discovery and analysis. The report is created by the report objects own create function (see `pmf_scripts.md` for further information).