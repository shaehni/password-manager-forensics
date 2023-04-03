#!/bin/python3

"""
Password Manager Forensics (PMF) Module for Bitwarden
This file contains all the functions to extract forensic artefacts from a Bitwarden Windows desktop application.
"""

# Imports
import codecs
import hashlib
import hmac
import io
import json
import re
from base64 import b64decode, b64encode
from binascii import Incomplete, hexlify

import requests
import yara
from Crypto.Cipher import AES
from hkdf import hkdf_expand
from tqdm import tqdm
from termcolor import colored

import Modules.pmf_reporter as reporter


# Object to store encrypted vault items
class Ciphertext:
    def __init__(self, text: str):
        self.encryption_type, t = text.split('.', 1)
        self.iv, self.data, self.mac = (b64decode(b) for b in t.split('|', 2))


class Decryptor:
    def __init__(self, key: bytes, mac: bytes):
        self.key = key
        self.mac = mac

    def decrypt(self, msg: Ciphertext) -> bytes:
        # Verify MAC, if provided
        if self.mac != bytes(0):
            mac = hmac.new(self.mac, msg.iv + msg.data, hashlib.sha256)
            assert mac.digest() == msg.mac

        # Decrypt
        c = AES.new(self.key, AES.MODE_CBC, msg.iv)
        data = c.decrypt(msg.data)

        # remove PKCS#7 padding
        pad_len = data[-1]
        return data[:-pad_len]


# Get number of PBKFD iterations from the login API
def get_pbkdf_iterations(email: str) -> int:
    api = 'https://vault.bitwarden.com/identity/accounts/prelogin'
    header = {"Content-Type": "application/json"}
    data = '{"email":"' + email + '"}'

    try:
        r = requests.post(api, data=data, headers=header)
    except requests.exceptions.RequestException:
        print(colored('[!] Connection error to Bitwarden login API. Could not fetch PBKDF iterations', 'red'))
        return 0
    else:
        if r.status_code == 200:
            return r.json()['kdfIterations']
        else:
            return 0


# Load data.json and return relevant account artefacts as dictionary
def get_file_artefacts(datafile: io.FileIO, r: reporter.Report) -> dict:
    result = dict()

    try:
        d = json.loads(datafile.read())
    except FileNotFoundError:
        print(colored('[!] data.json not found. Check --files for correct path', 'red'))
        return result
    except json.JSONDecodeError:
        print(colored('[!] data.json is not a valid JSON file', 'red'))
        return result

    # Get full data if user is logged in
    if len(d['authenticatedAccounts']) > 0:
        a = d['authenticatedAccounts'][0]
        result['logged_in'] = True

        # Account data
        extr = {'User name': 'name', 'Email': 'email', 'Last Synchsonization': 'lastSync',
                'PBKDF Iterations': 'kdfIterations'}
        for x, y in extr.items():
            result[y] = d[a]['profile'][y]
            r.add('Account Info', {x: str(d[a]['profile'][y])})

        # Encrypted Keys
        result['symmetricKey'] = d[a]['keys']['cryptoSymmetricKey']['encrypted']
        result['privateKey'] = d[a]['keys']['privateKey']['encrypted']

        # Encrypted PIN
        result['pin'] = d[a]['settings']['pinProtected']['encrypted']

        # Vault items
        result['vault'] = d[a]['data']['ciphers']['encrypted']

        # Password Generator
        # Settings (Report only)
        extr = {'Password Length': 'length', 'Numbers': 'number', 'Uppercase Letters': 'uppercase',
                'Lowercase Letters': 'lowercase', 'Special Characters': 'special'}
        settings = dict()
        for x, y in extr.items():
            settings.update({x: str(d[a]['settings']['passwordGenerationOptions'][y])})
        r.add('Password Generator', {'Settings': settings})

        # History
        try:
            result['pwgen_history'] = d[a]['data']['passwordGenerationHistory']['encrypted']
        except KeyError:
            pass  # Ignore if history does not exist

    # Fall-back if user is not logged in
    else:
        result['logged_in'] = False
        result['email'] = d['global']['rememberedEmail']
        if result['email'] != '':
            result['kdf'] = get_pbkdf_iterations(result['email'])

    return result


# Scan memory dump for passwords
def scan_memory_for_pw(file: io.FileIO) -> tuple[str, list]:
    pattern = '^[A-Za-z0-9!@#$%&*^]+$'  # Characters used by Bitwarden's password generator
    false_positives = ['false', 'true', 'Window', 'Bitwarden', 'Password', 'Wrap', 'Binding', 'Object', 'Helper',
                       'Address', 'List', 'Attachments', 'View']  # Known false positives
    master_password = ''
    vault_passwords = []

    # Load Yara rules and apply it to memory dump
    yara_rule = yara.compile('Modules/bitwarden.yara')
    print('Scanning memory dump (this can take a while)...')
    matches = yara_rule.match(data=file.read())
    file.close()

    # Iterate over matches
    for match in matches:
        if match.rule == 'vault_password':
            for s in match.strings:
                # Convert content part from hex to string
                try:
                    hex_str = hexlify(s[2])
                    # String length at offset 8 bytes
                    l_length = int(hex_str[16:18], 16)
                    # Strings starts at offset 12 bytes
                    l_str = codecs.decode(hex_str[24:(24+l_length*2)], 'hex').decode('utf-8')
                except (UnicodeError, Incomplete):
                    continue  # Ignore matches that cannot be decoded

                # Filter unlikely strings
                if l_length >= 8 and re.match(pattern, l_str) and not re.match('^([0-9]+|[A-Z]+)$', l_str):
                    # Filter known false positives
                    if not any(fp in l_str for fp in false_positives):
                        # Check for duplicates
                        if l_str not in vault_passwords:
                            vault_passwords.append(l_str)

        elif match.rule == 'master_password':
            for s in match.strings:
                # Convert content part from hex to string
                try:
                    l_str = s[2][20:-2].decode('utf-8')
                except UnicodeError:
                    continue  # Ignore matches that cannot be decoded

                # Extract master password
                master_password = l_str.split(' ')[1]

    return master_password, vault_passwords


# Read password list for brute-forcing
def read_pws(file: io.FileIO) -> list:
    pw_list = []
    for pw in file:
        pw_list.append(str(pw).split('\n')[0])
    return pw_list


# Main Extraction Function
def extract(datafile: io.FileIO, memory_dump: io.FileIO, master_pw: str, brute_force: io.FileIO,
            brute_force_pin: io.FileIO, report_folder: str) -> bool:
    print(colored('PMF Extractor for Bitwarden', attrs=['bold', 'underline']) + '\n')

    # Instantiate report object
    chapters = ['Account Info', 'Cryptography', 'Vault Data', 'Password Generator', 'Memory Analysis']
    r = reporter.Report(chapters)

    # Extract artefacts from data.json
    print(colored('### Analysing data.json', 'yellow'))
    if datafile:
        print('Loading data.json...')
        acc_data = get_file_artefacts(datafile, r)
        if len(acc_data) > 0:
            if acc_data['logged_in']:
                print(colored('Acount data found for: {} ({})'.format(acc_data['email'], acc_data['name']), 'green'))
                print('{} encrypted vault items found.'.format(len(acc_data['vault'])))
                if acc_data['pin'] is not None:
                    print('PIN-encrypted master key found! PIN brute-force possible.')
                    r.add('Account Info', {'PIN': 'PIN-encrypted master key found'})
            elif acc_data['email'] != '':
                print('User logged out. Password brute-force possible:\n' +
                      'E-Mail: {}\nPBKDF iterations: {}'.format(acc_data['email'], acc_data['kdf']))
            else:
                print('No artefacts could be extracted.')
    else:
        print('[i] No extracted files provided. Skipping file analysis.')
        acc_data = {}

    # Extract artefacts from memory dump
    print(colored('\n### Loading and analysing memory dump', 'yellow'))
    if memory_dump:
        r.add('Memory Analysis', {'Memory Dump File': memory_dump.name})
        master_pw, vault_pws = scan_memory_for_pw(memory_dump)

        # Master password
        if len(master_pw) > 0:
            print(colored('Possible master password found: {}'.format(master_pw), 'green'))
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

    # Access vault data
    print(colored('\n### Analysing Vault Data', 'yellow'))
    if len(acc_data) > 0 and (master_pw != '' or brute_force or brute_force_pin):
        sym_key = ()

        # Case 1: Master password (list) provided by user or found in memory dump
        if master_pw != '' or brute_force:
            password_list = [master_pw]
            if brute_force:
                password_list += read_pws(brute_force)
                print('Trying {} master passwords...'.format(len(password_list)))

            for master_pw in password_list:
                try:
                    # Calculate master key
                    master_key = hashlib.pbkdf2_hmac('sha256', master_pw.encode('utf-8'),
                                                     acc_data['email'].encode('utf-8'), acc_data['kdfIterations'])
                    streched_master_key = (hkdf_expand(master_key, b'enc', 32, hashlib.sha256),
                                           hkdf_expand(master_key, b'mac', 32, hashlib.sha256))
                except ValueError as e:
                    print(colored('[!] Could not calculate master key: {}'.format(e), 'red'))
                else:
                    r.add('Cryptography', {'Master Key': b64encode(master_key)})
                    # Decrypt symmetric vault key
                    dc = Decryptor(streched_master_key[0], streched_master_key[1])
                    try:
                        sym_key_data = dc.decrypt(Ciphertext(acc_data['symmetricKey']))
                    except AssertionError:
                        if brute_force:
                            continue
                        else:
                            print(colored('[!] Provided master password invalid.', 'red'))
                    else:
                        sym_key = (sym_key_data[:32], sym_key_data[32:64])
                        r.add('Cryptography', {'Master Password': master_pw,
                                               'Symmetric Vault Key': {
                                                   'Encryption Key': b64encode(sym_key[0]).decode('utf-8'),
                                                   'MAC': b64encode(sym_key[1]).decode('utf-8')}})
                        if brute_force:
                            print(colored('Valid master password found: {}'.format(master_pw), 'green'))
                        break

        # Case 2: PIN brute-force
        elif brute_force_pin:
            if acc_data['pin'] is None:
                print(colored('[!] Encrypted master key not available. Skipping PIN brute-forcing.'))
            else:
                pins = read_pws(brute_force_pin)
                print('Brute-forcing PIN...')
                for pin in tqdm(pins):
                    try:
                        # Calculate pin key
                        pin_key = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), acc_data['email'].encode('utf-8'),
                                                      acc_data['kdfIterations'])
                        stretched_pin_key = hkdf_expand(pin_key, b'enc', 32, hashlib.sha256)
                    except ValueError as e:
                        print(colored('[!] Could not calculate pin key: {}'.format(e), 'red'))
                    else:
                        # Decrypt master key with pin key
                        dc = Decryptor(stretched_pin_key, bytes(0))
                        try:
                            master_key = dc.decrypt(Ciphertext(acc_data['pin']))
                            stretched_master_key = (hkdf_expand(master_key, b'enc', 32, hashlib.sha256),
                                                    hkdf_expand(master_key, b'mac', 32, hashlib.sha256))
                        except ValueError as e:
                            print(colored('[!] Could not calculate master key: {}'.format(e), 'red'))
                        else:
                            # Decrypt symmetric vault key
                            dc = Decryptor(stretched_master_key[0], stretched_master_key[1])
                            try:
                                sym_key_data = dc.decrypt(Ciphertext(acc_data['symmetricKey']))
                            except AssertionError:
                                continue
                            else:
                                sym_key = (sym_key_data[:32], sym_key_data[32:64])
                                r.add('Cryptography', {'PIN': pin,
                                                       'Master Key': b64encode(master_key).decode('utf-8'),
                                                       'Symmetric Vault Key': {
                                                           'Encryption Key': b64encode(sym_key[0]).decode('utf-8'),
                                                           'MAC': b64encode(sym_key[1]).decode('utf-8')}})
                                print(colored('Found valid PIN: {}'.format(pin), 'green'))
                                break

        # Decrypting vault data
        if sym_key != ():
            dc = Decryptor(sym_key[0], sym_key[1])
            vault_count = 0
            for item in acc_data['vault']:
                i = acc_data['vault'][item]
                try:
                    item_name = dc.decrypt(Ciphertext(i['name'])).decode('utf-8')
                except (AssertionError, AttributeError):
                    item_name = ''
                try:
                    item_user = dc.decrypt(Ciphertext(i['login']['username'])).decode('utf-8')
                except (AssertionError, AttributeError):
                    item_user = ''
                try:
                    item_pw = dc.decrypt(Ciphertext(i['login']['password'])).decode('utf-8')
                except (AssertionError, AttributeError):
                    item_pw = ''
                try:
                    item_notes = dc.decrypt(Ciphertext(i['notes'])).decode('utf-8')
                except (AssertionError, AttributeError):
                    item_notes = ''
                r.add('Vault Data', {item_name: {'User': item_user, 'Password': item_pw,
                                                 'Notes': item_notes}})
                vault_count += 1
            print(colored('{} vault items successfully decrypted.'.format(vault_count), 'green'))

        else:
            print(colored('\n[!] Could not decrypt vault: unable to get encryption key.', 'red'))

    elif len(acc_data) > 0:
        print(colored('\n[!] Could not decrypt vault: master password not available.', 'red'))

    else:
        print(colored('\n[!] Could not decrypt vault: vault data not available (check --files).', 'red'))

    # Create Report
    if len(acc_data) > 0:
        print(colored('\n### Creating Report', 'yellow'))
        try:
            file = r.save(report_folder, 'report')
        except FileExistsError:
            print(colored('[!] Report file already exists. Will not overwrite, skipping...', 'red'))
        else:
            print('Report saved: {}'.format(file))

    return True
