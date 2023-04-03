#!/bin/python3

"""
Password Manager Forensics (PMF) Extractor
This script loads all functions to extract forensic artefacts from password managers. These functions are
defined in a separate module for each password manager. At the moment, the Windows desktop apps of Bitwarden
and KeePass are supported.
"""

# Imports
import argparse

import Modules.bitwarden as bitwarden
import Modules.keepass as keepass

# Settings
version = '1.0'
available_pwm = ['bitwarden', 'keepass']

# Argument Parser
ap = argparse.ArgumentParser(usage='%(prog)s [Password Manager] [Options]',
                             description='Password Manager Forensics (PMF) v' + version +
                                         ' – This app extracts relevant artefacts from password manager files and '
                                         'memory dumps.',
                             epilog='\b')

# General Arguments
ap.add_argument('--report', type=str, metavar='PATH', default='PMF_Report',
                help='Path to folder where the report is created (default: ./PMF_Report)')
sub = ap.add_subparsers(metavar='Password Manager', dest='pwm', required=True,
                        help='Select Password Manager (Available: ' + ', '.join(available_pwm) + ')')

# Arguments for Bitwarden
ap_bitwarden = sub.add_parser('bitwarden', usage='pmf_extractor.py bitwarden [options]')
ap_bitwarden.add_argument('--data-file', type=argparse.FileType('r'), metavar='FILE',
                          help='data.json file (default: none)')
ap_bitwarden.add_argument('--memory-dump', type=argparse.FileType('rb'), metavar='FILE',
                          help='Path to memory dump file (default: none)')
ap_bitwarden.add_argument('--master-pw', type=str, metavar='Password', default='',
                          help='Manually provide the master password, if known')
ap_bitwarden.add_argument('--brute-force', type=argparse.FileType('r'), metavar='FILE',
                          help='Brute-force Master Password. Path to password list (default: none)')
ap_bitwarden.add_argument('--brute-force-pin', type=argparse.FileType('r'), metavar='FILE',
                          help='Brute-force PIN. Path to password list (default: none)')

# Arguments for KeePass
ap_keepass = sub.add_parser('keepass', usage='pmf_extractor.py keepass [options]')
ap_keepass.add_argument('--database', type=argparse.FileType('rb'), metavar='FILE',
                        help='KeePass database file (.kdbx) (default: none)')
ap_keepass.add_argument('--config-file', type=argparse.FileType('rb'), metavar='FILE',
                        help='KeePass configuration file (KeePass.config.xml) (default: none)')
ap_keepass.add_argument('--memory-dump', type=argparse.FileType('rb'), metavar='FILE',
                        help='Path to memory dump file (default: none)')
ap_keepass.add_argument('--master-pw', type=str, metavar='Password', default='',
                        help='Manually provide the master password, if known')
ap_keepass.add_argument('--key-file', type=argparse.FileType('r'), metavar='FILE',
                        help='Path to key file (default: none)')
ap_keepass.add_argument('--brute-force', type=argparse.FileType('r'), metavar='FILE',
                        help='Path to password list (default: none)')

args = ap.parse_args()


# Start Main
def main():
    if args.pwm == 'bitwarden':
        bitwarden.extract(args.data_file, args.memory_dump, args.master_pw, args.brute_force,
                          args.brute_force_pin, args.report)

    elif args.pwm == 'keepass':
        keepass.extract(args.database, args.config_file, args.memory_dump, args.master_pw, args.key_file,
                        args.brute_force, args.report)


if __name__ == '__main__':
    main()
