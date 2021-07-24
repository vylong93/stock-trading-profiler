#!/usr/bin/env python3

import argparse
from argparse import ArgumentParser

def convert_xls_to_csv(files):
    for file in files:
        print('TODO: convert', file, 'to csv format')

class ExtendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        items = getattr(namespace, self.dest) or []
        items.extend(values)
        setattr(namespace, self.dest, items)

def main():
    __version__ = "1.0"

    parser = ArgumentParser(description='Tool for convert xls files to csv (UTF-8 Comma delimited)')
    parser.register('action', 'extend', ExtendAction)
    parser.add_argument('-v', '--version', action='version', version='%(prog)s v{}'.format(__version__))
    parser.add_argument('-f', '--files', nargs='+', action='extend', help='xls files input')

    args = parser.parse_args()

    methods = [x for x in (args.files, None) if x is not None]

    if len(methods) != 1:
        raise RuntimeError('Specify exactly files\n')

    if args.files:
        convert_xls_to_csv(args.files)
    else:
        raise RuntimeError('Provide xls files path')

if __name__ == "__main__":
    main()
