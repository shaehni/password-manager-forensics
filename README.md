# Password Manager Forensics (PMF)
This repository is part of my master thesis "[Password Managers in Digital Forensics][3]". Password Manager Forensics (PMF) consists of definitions of relevant forensic artefacts that can be extracted from two password manager applications (Bitwarden and KeePass), as well as python scripts to perform said extraction.

## Preparation
`$ pip install -r requirements.txt`

## Usage
### Application Identifier
`pmf_appident.py`: This script loads known application paths and relevant filenames from a pre-definition file, and searches the file system for them. Identified relevant files are copied into a folder. Arguments:

- `--search-path [file path]`: Change the root directory to search for artefacts (default: C:/)
- `--extract-to [file path]`: Define the folder where artefacts are extracted to (default: ./extract)
- `--predefinition [file path]`: Path to the pre-definition file (json) (default: Definitions/pmf_apps.json)

### Extractor
`pmf_extractor.py`: This script scans the extracted files and/or a memory dump for forensic artefacts, analyses and processes the artefacts, and creates a report with the results. Arguments:

- `--report [folder]`: Path to the directory where the report will be saved (default: ./report)
- `[password manager]`: Select the password manager application from which artefacts shall be extracted (Available in this version: bitwarden, keepass). Every password manager module accepts application-specific arguments. See the respective module description for further information.

See [Definitions/bitwarden_functions.md][1] and [Definitions/keepass_functions.md][2] for further information about application-specific arguments.

[1]:https://github.com/shaehni/password-manager-forensics/blob/main/Definitions/bitwarden_functions.md
[2]:https://github.com/shaehni/password-manager-forensics/blob/main/Definitions/keepass_functions.md
[3]:https://urn.kb.se/resolve?urn=urn:nbn:se:su:diva-219709
