#!/bin/python3

"""
Password Manager Forensics (PMF) Module for KeePass
This file contains all the functions to extract forensic artefacts from a KeePass Windows desktop application.
"""

# Imports
import codecs
import io
import re
import xml.etree.ElementTree as Et
from base64 import b64encode

from binascii import Incomplete, hexlify, unhexlify
import pykeepass
from termcolor import colored
import yara

import Modules.pmf_reporter as reporter


# Analyze database file
def get_database_info(f: io.FileIO, r: reporter.Report) -> bool:
    # Verify file signature (KeePass 2.x file: 03 D9 A2 9A 67 FB 4B B5)
    if f.read(8) != unhexlify('03d9a29a67fb4bb5'):
        return False

    # Read file version
    file_version_minor = int.from_bytes(f.read(2), 'little')
    file_version_major = int.from_bytes(f.read(2), 'little')
    r.add('Database', {'File Version': '{}.{}'.format(file_version_major, file_version_minor)})

    # Read variable-length headers
    header = dict()
    while True:
        header_type = int.from_bytes(f.read(1), 'little')
        header_length = int.from_bytes(f.read(2), 'little')

        if header_type == 0:  # End of header
            break
        else:
            header_data = f.read(header_length)
            if header_type == 3:  # Compression flag
                header.update({'Compressed (gzip)': (int.from_bytes(header_data, 'little') == 1)})
            elif header_type == 4:  # Master seed
                header.update({'Master Seed': b64encode(header_data).decode('utf-8')})
            elif header_type == 5:  # Transform seed
                header.update({'Transform Seed': b64encode(header_data).decode('utf-8')})
            elif header_type == 6:  # Transform rounds
                header.update({'Transform rounds': int.from_bytes(header_data, 'little')})
            elif header_type == 7:  # Initiatlisation vector
                header.update({'Initialisation vector': b64encode(header_data).decode('utf-8')})

    r.add('Database', {'Header Information': header})
    return True


# Analyze config file
def parse_config_file(f: io.FileIO, r: reporter.Report) -> bool:
    xml = Et.parse(f)

    # Known databases and corresponding security configurations
    for i, e in enumerate(xml.find('Defaults/KeySources')):
        db = dict()
        if e.find('DatabasePath') is not None:
            db.update({'Database Path': e.find('DatabasePath').text})
        if e.find('Password') is not None:
            db.update({'Password used': e.find('Password').text})
        if e.find('KeyFilePath') is not None:
            db.update({'Key File': e.find('KeyFilePath').text})
        r.add('Config', {'Database {}'.format(i): db})

    # Last used databases
    db = []
    for e in xml.find('Application/MostRecentlyUsed/Items'):
        if e.find('Path') is not None:
            db.append(e.find('Path').text)
    r.add('Config', {'Last Used Database Files': db})

    # Password generator configuration
    pwg = dict()
    for e in xml.find('PasswordGenerator/LastUsedProfile'):
        pwg.update({e.tag: e.text})
    r.add('Config', {'Password Generator Settings': pwg})

    return True


# Scan memory dump for passwords
def scan_memory_for_pw(file: io.FileIO) -> tuple[list, list]:
    master_passwords = []
    vault_passwords = []
    false_positives = ['Windows', 'Program', 'Drive', 'System', 'Intel', 'values', 'Users',
                       'Explorer', 'Path']  # Known false positives

    # Load Yara rules and apply it to memory dump
    yara_rule = yara.compile('Modules/keepass.yara')
    print('Scanning memory dump (this can take a while)...')
    matches = yara_rule.match(data=file.read(), timeout=60)
    file.close()

    # Iterate over matches
    for match in matches:
        if match.rule == 'vault_password':
            for s in match.strings:
                # Convert content part from hex to string
                try:
                    hex_str = hexlify(s[2])
                    # String length at offset 9 bytes
                    l_length = int(hex_str[18:20], 16)
                    # String starts at offset 17 bytes
                    l_str = codecs.decode(hex_str[34:(34 + l_length * 2)], 'hex').decode('utf-8')
                except (UnicodeError, Incomplete):
                    continue  # Ignore matches that cannot be decoded

                # Filter unlikely strings
                if l_length >= 8 and l_str.isprintable() and not re.match('^([0-9]+|[A-Z_]+)$', l_str):
                    # Filter known false positives
                    if not any(fp in l_str for fp in false_positives):
                        # Check for duplicates
                        if l_str not in vault_passwords:
                            vault_passwords.append(l_str)

        elif match.rule == 'master_password':
            for s in match.strings:
                # Convert content part from hex to string
                try:
                    hex_str = hexlify(s[2])
                    l_str = codecs.decode(hex_str[16:-20], 'hex').decode('utf-8')  # String starts at offset 8 bytes
                except (UnicodeError, Incomplete):
                    continue  # Ignore matches that cannot be decoded

                # Remove every second character (padding byte)
                pw = ''
                for i, c in enumerate(l_str):
                    if i % 2 == 0:
                        pw += c

                # Check for plausability and duplicates
                if pw not in master_passwords and len(pw) >= 8 and pw.isprintable():
                    master_passwords.append(pw)

    return master_passwords, vault_passwords


# Read password list for brute-forcing
def read_pws(file: io.FileIO) -> list:
    pw_list = []
    for pw in file:
        pw_list.append(pw.split('\n')[0])
    return pw_list


# Main Extraction Function
def extract(database: io.FileIO, config_file: io.FileIO, memory_dump: io.FileIO, master_pw: str, key_file: io.FileIO,
            brute_force: io.FileIO, report_folder: str) -> bool:
    print(colored('PMF Extractor for KeePass', attrs=['bold', 'underline']) + '\n')

    # Instantiate report object
    chapters = ['Database', 'Cryptography', 'Vault Data', 'Config', 'Memory Analysis']
    r = reporter.Report(chapters)

    # Extract artefacts from database file
    print(colored('### Analysing KeePass Database', 'yellow'))
    if database:
        print('Loading {}...'.format(database.name))
        r.add('Database', {'Database File': database.name})
        if get_database_info(database, r):
            print(colored('Database header information successfully extracted', 'green'))
        else:
            print(colored('[!] File is not a valid KeePass database file. Skipping analysis...', 'red'))
    else:
        print('[i] No database file provided. Skipping file analysis.')

    # Extract artefacts from config file
    print(colored('\n### Analysing KeePass Configuration File', 'yellow'))
    if config_file:
        print('Loading {}...'.format(config_file.name))
        try:
            parse_config_file(config_file, r)
        except (UnicodeError, TypeError):
            print(colored('[!] Could not parse config file. Did you provide the correct file?', 'red'))
        else:
            print(colored('Configuration file successfully parsed', 'green'))
    else:
        print('[i] No configuration file provided. Skipping file analysis.')

    # Extract artefacts from memory dump
    print(colored('\n### Analysing Memory', 'yellow'))
    if memory_dump:
        r.add('Memory Analysis', {'Memory Dump File': memory_dump.name})
        master_pws, vault_pws = scan_memory_for_pw(memory_dump)

        # Master password
        if len(master_pws) > 0:
            print(colored('{} possible master passwords found.'.format(len(master_pws)), 'green'))
        else:
            print('No master password found.')

        # Vault passwords
        if len(vault_pws) > 0:
            print(colored('{} possible vault password(s) found.'.format(len(vault_pws)), 'green'))
            r.add('Memory Analysis', {'Possible Vault Passwords': vault_pws})
        else:
            print('No vault password(s) found.')
    else:
        print('[i] No memory dump file provided. Skipping memory analysis.')
        master_pws = []

    # Brute-Force: Add password list to possible master passwords
    if brute_force:
        try:
            master_pws += read_pws(brute_force)
        except IOError:
            print(colored('[!] Could not open password list. Skipping brute-force...', 'red'))

    # Access KeePass database
    print(colored('\n### Extracting Vault Data', 'yellow'))
    kp = False
    if database and (len(master_pws) > 0 or master_pw != '' or key_file):
        # Verifying master password and/or key file
        # Case 1: Master password provided by user
        if master_pw != '':
            try:
                if key_file:
                    kp = pykeepass.PyKeePass(database.name, master_pw, key_file.name)
                else:
                    kp = pykeepass.PyKeePass(database.name, master_pw)
            except pykeepass.pykeepass.CredentialsError:
                print(colored('[!] Provided master password and/or keyfile invalid.', 'red'))
            else:
                r.add('Cryptography', {'Master Password': master_pw,
                                       'Key File': key_file.name,
                                       'Master Key': b64encode(kp.transformed_key).decode('utf-8')})

        # Case 2: Master password found in memory dump
        elif len(master_pws) > 0:
            success = False
            for pw in master_pws:
                print('Trying master password "{}"...'.format(pw))
                try:
                    if key_file:
                        kp = pykeepass.PyKeePass(database.name, pw, key_file.name)
                    else:
                        kp = pykeepass.PyKeePass(database.name, pw)
                except pykeepass.pykeepass.CredentialsError:
                    continue
                else:
                    print(colored('Valid master password: {}'.format(pw), 'green'))
                    r.add('Cryptography', {'Master Password': pw,
                                           'Key File': key_file.name,
                                           'Master Key': b64encode(kp.transformed_key).decode('utf-8')})
                    success = True
                    break
            if not success:
                print(colored('[!] Master password validation failed. Could not decrypt vault. (Missing key file?)',
                              'red'))

        # Case 3: No master password, try only key file
        else:
            try:
                kp = pykeepass.PyKeePass(database.name, None, key_file.name)
            except pykeepass.pykeepass.CredentialsError:
                print(colored('[!] Could not decrypt vault with key file alone.', 'red'))
            else:
                r.add('Cryptography', {'Master Password': 'None',
                                       'Key File': key_file.name,
                                       'Master Key': b64encode(kp.transformed_key).decode('utf-8')})
    elif database:
        print(colored('[!] Could not decrypt vault: neither master password nor key file available.', 'red'))
    else:
        print(colored('[!] Could not decrypt vault: KeePass database not available (check --database).', 'red'))

    # Extract vault items
    if isinstance(kp, pykeepass.PyKeePass):
        print('Successfully accessed KeePass database. Extracting vault items...')
        vault_count = 0
        for item in kp.entries:
            r.add('Vault Data', {item.title: {'User': item.username, 'Password': item.password,
                                              'Notes': item.notes, 'Custom Fields': item.custom_properties}})
            vault_count += 1
        print(colored('{} vault items successfully extracted.'.format(vault_count), 'green'))

    # Create Report
    print(colored('\n### Creating Report', 'yellow'))
    try:
        file = r.save(report_folder, 'report')
    except FileExistsError:
        print(colored('[!] Report file already exists. Will not overwrite, skipping...', 'red'))
    else:
        print('Report saved: {}'.format(file))

    return True
