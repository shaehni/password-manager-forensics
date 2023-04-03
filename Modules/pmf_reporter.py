#!/bin/python3

"""
Password Manager Forensics (PMF) Reporter Module
This file contains the Report object as well as the functions to create a report.
"""

# Imports
import os

from datetime import datetime
from typing import TextIO


class Report:
    chapters = dict()

    def __init__(self, chapters: list):
        for chapter in chapters:
            self.chapters[chapter] = {}

    def add(self, chapter: str, element: dict):
        if chapter not in self.chapters:
            raise ValueError('Chapter not defined')
        else:
            self.chapters[chapter].update(element)

    def save(self, path: str, name: str) -> str:
        f = create_report_file(path, name)
        return os.path.join(path, create_report(self, f))


def create_report_file(path: str, name: str) -> TextIO:
    # Create folder if necessary
    if not os.path.isdir(path):
        os.makedirs(path)
    os.chdir(path)

    # Complete file name
    name = name + datetime.now().strftime('-%Y%m%d-%H%M') + '.txt'

    # Create and return file object
    if os.path.isfile(name):
        raise FileExistsError
    else:
        f = open(name, 'w', encoding='utf-8')
        return f


def create_report(data: Report, file: TextIO) -> str:
    # Iterate over chapters
    for chapter in data.chapters:
        file.write('# ######\n# ' + chapter + '\n# ######\n\n')

        # Iterate over items
        for item, value in data.chapters[chapter].items():
            # Value is string
            if type(value) == str:
                file.write(item + ': ' + str(value) + '\n')
            # Value is dict
            elif type(value) == dict:
                file.write(item + ':\n')
                for i, v in value.items():
                    file.write('- ' + i + ': ' + str(v) + '\n')
            # Value is list
            elif type(value) == list:
                file.write(item + ':\n')
                for e in value:
                    file.write('- ' + str(e) + '\n')
            file.write('\n')
        file.write('\n\n')

    # Footer
    file.write('Report created on {} by PMF Reporter'.format(datetime.now().strftime('%Y-%m-%d %H:%M')))
    return file.name
