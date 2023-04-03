# Password Manager Forensics – Scripts
PMF includes different scripts to automate the extraction process of forensic artefacts from password manager applications. This file documents these scripts.

## Application Identifier
`pmf_appident.py`: This script loads known application paths and relevant filenames from a pre-definition file, and searches the file system for them. Identified relevant files are copied into a folder. Arguments:

- `--search-path [file path]`: Change the root directory to search for artefacts (default: C:/)
- `--extract-to [file path]`: Define the folder where artefacts are extracted to (default: ./extract)
- `--predefinition [file path]`: Path to the pre-definition file (json) (default: Definitions/pmf_apps.json)

## Extractor
`pmf_extractor.py`: This script scans the extracted files and/or a memory dump for forensic artefacts, analyses and processes the artefacts, and creates a report with the results. Arguments:

- `--report [folder]`: Path to the directory where the report will be saved (default: ./report)
- `[password manager]`: Select the password manager application from which artefacts shall be extracted (Available in this version: bitwarden, keepass). Every password manager module accepts application-specific arguments. See the respective module description for further information.

## Reporter
`pmf_reporter.py`: This module defines the `Report` class and corresponding functions. A `Report` is instantiated by providing a list of chapters. Functions:

- `add(chapter, element)`: This function adds data that will be printed under the given chapter. The element argument is a dictionary `{name: value}` where `name` is the string how it will appear in the report, and `value` is either a string, a list, or a dictionary.
- `save(path, name)`: This function creates a report file containing all data elements stored in the `Report` object. The file is created under the given `path`. The current date and time is automatically added to the `name` of the file.

The created report file is a text document containing all chapters as headings with corresponding data listed beneath. Chapters are sorted according to the list order when the object was instantiated. Chapter data is sorted in the order it was added.