#!/bin/python3

"""
Password Manager Forensics (PMF) Application Identifier
This script loads known application directory paths and known relevant file names from a pre-definition
file, searches the file system for these files, and extracts them to a folder.
"""

# Imports
import argparse
import json
import os
import shutil
from glob import glob

from termcolor import colored

# Settings
version = '1.0'

# Argument Parser
ap = argparse.ArgumentParser(usage='%(prog)s [--search-path PATH] [--predefinition FILE]',
                             description='Password Manager Forensics (PMF). Application Identifier v' + version +
                             ' – This app searches for password manager applications and '
                             'copies relevant files into an extraction folder.',
                             epilog='\b')

ap.add_argument('--predefinition', type=argparse.FileType('r'), metavar='FILE',
                default=os.path.join('Definitions', 'pmf_apps.json'),
                help='Pre-Definition file (json) with search patterns (default: Definitions/pmf_apps.json')
ap.add_argument('--search-path', type=str, default='C:\\',
                help='Path to search for relative Folders (Default: C:\\)')
ap.add_argument('--extract-to', type=str, default='extract', metavar="PATH",
                help='Path to folder where artefacts are extracted to (Default: .\\extract)')
args = ap.parse_args()


class PmApp:
    def __init__(self, name: str, data: dict):
        self.name = name
        self.results = []

        try:
            self.abs_paths = data["absolute_paths"]["directories"]
        except KeyError:
            self.abs_paths = []
        try:
            self.abs_files = data["absolute_paths"]["files"]
        except KeyError:
            self.abs_files = {}
        try:
            self.rel_paths = data["relative_paths"]["directories"]
        except KeyError:
            self.rel_paths = []
        try:
            self.rel_files = data["relative_paths"]["files"]
        except KeyError:
            self.rel_files = {}


class Pm:
    def __init__(self, name: str):
        self.name = name
        self.apps = []

    def addapp(self, app: PmApp):
        self.apps.append(app)


# Open and parse the pre-definition file (json)
def load_predefinition() -> any:
    json_raw = args.predefinition.read()
    args.predefinition.close()
    return json.loads(json_raw)


# Create folder to copy the extracted artefacts to and return path
def get_extract_dir(pm: str) -> str:
    extract_dir = os.path.join(args.extract_to, pm)
    if not os.path.isdir(extract_dir):
        os.makedirs(extract_dir)
    return os.path.join(extract_dir)


# Perform artefact search based on pre-definition information
def search_for_artefacts(pm_list: list):
    # Absolute paths
    for pm in pm_list:
        for app in pm.apps:
            for path in app.abs_paths:
                for file_desc, file_name in app.abs_files.items():
                    d = os.path.join(args.search_path, path, file_name)
                    for f in glob(d):
                        app.results.append((file_desc, f))

    # Relative paths
    for root, dirs, files in os.walk(args.search_path):
        # Matching folders
        for pm in pm_list:
            for app in pm.apps:
                for path in app.rel_paths:
                    for d in glob(os.path.join(root, path)):
                        # Directories that match the relative pattern; looking for files
                        for file_desc, file_name in app.rel_files.items():
                            for f in glob(os.path.join(d, file_name)):
                                app.results.append((file_desc, f))


# Copy the defined relevant artefacts into the extraction folder
def extract_artefacts(extract_dir_pm: str, artefact_list: list) -> list[tuple]:
    result = []
    for artefact in artefact_list:
        artefact_desc, artefact_path = artefact
        extraction_path = os.path.join(extract_dir_pm, os.path.basename(artefact_path))

        # Don't overwrite existing files
        if os.path.isfile(extraction_path):
            i = 1
            path, extension = os.path.splitext(extraction_path)
            while os.path.isfile(extraction_path):
                extraction_path = path + ' (' + str(i) + ')' + extension
                i += 1

        # Copy artefact
        shutil.copyfile(artefact_path, extraction_path)
        result.append((artefact_desc, artefact_path + ' -> ' + os.path.basename(extraction_path)))
    return result


# Start Main
def main():
    print(colored('PMF App Identifier', attrs=['bold', 'underline']) + '\n')

    # Load Pre-Definitions
    print(colored('### Loading definition file', 'yellow'))
    try:
        pd = load_predefinition()
    except FileNotFoundError:
        print(colored('[!] Pre-definition file not found. Check --predefinition for correct path', 'red'))
        return 0
    except json.JSONDecodeError:
        print(colored('[!] Pre-definition file is not a valid JSON file', 'red'))
        return 0

    print('Definition loaded for {} password manager(s): {}'.format(len(pd), ', '.join(pd)))

    # Instantiate objects with pre-definition data
    pm_list = []
    for pm, apps in pd.items():
        p = Pm(pm)
        for app, data in apps.items():
            p.addapp(PmApp(app, data))
        pm_list.append(p)

    # Search for directories that match the patterns, store results in app object
    print('Searching for files (this might take a while)...\n')
    search_for_artefacts(pm_list)

    # Extract artefacts
    for pm in pm_list:
        print(colored('### Results for {}'.format(pm.name), 'yellow'))

        # Loop through results and copy artefacts to extraction folder
        extracted = False
        for app in pm.apps:
            if len(app.results) > 0:
                print('Found: {}'.format(app.name))

                # Prepare folder and extract artefacts
                try:
                    extract_dir_pm = get_extract_dir(os.path.join(pm.name, app.name))
                except OSError:
                    print(colored('[!] Could not create extraction folder. No files are copied', 'red'))
                else:
                    extracted_artefacts = extract_artefacts(extract_dir_pm, app.results)
                    for artefact in extracted_artefacts:
                        print('- {} ({})'.format(artefact[0], artefact[1]))
                    extracted = True

        if not extracted:
            print('No application files found')
        print()
    print(colored('App identification completed. Results in folder: {}\n'.format(args.extract_to), 'green'))


if __name__ == '__main__':
    main()
