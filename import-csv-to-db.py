#!/usr/bin/env python3

import argparse
from argparse import ArgumentParser


def import_csv_into_db(csv_file, db_file):
    print('TODO: import', csv_file, 'into', db_file)


def main():
    __version__ = "1.0"

    parser = ArgumentParser(description='Tool for import csv file into SQLite3 database file')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s v{}'.format(__version__))
    parser.add_argument('-f', '--file', help='csv file input')
    parser.add_argument('-db', '--database_file', help='SQLite3 database file')

    args = parser.parse_args()

    methods = [x for x in (args.file, args.database_file) if x is not None]

    if len(methods) != 2:
        raise RuntimeError('Specify exactly csv file and db file\n')

    if args.file and args.database_file:
        import_csv_into_db(args.file, args.database_file)
    else:
        raise RuntimeError('Provide csv and/or db files path')

if __name__ == "__main__":
    main()
