#!/usr/bin/env python3

import argparse
from argparse import ArgumentParser
import os
import sqlite3
import csv
import pandas as pd
from datetime import datetime
import re


def import_csv_into_db(csv_file, db_file):
    if not os.path.exists(csv_file):
        raise RuntimeError('Please provide correct path to csv file')

    db_conn = sqlite3.connect(db_file)
    data = pd.read_csv(csv_file)  # thousands=','
    data.to_sql('money_transaction', db_conn, if_exists='append', index=False)

    print('File [', csv_file, '] is imported into[', db_file, ']!\n')
    db_conn.close()


def correct_fields_type(db_file):
    if not os.path.exists(db_file):
        raise RuntimeError('Please provide correct path to db file')

    try:
        db_conn = sqlite3.connect(db_file)
        cur = db_conn.cursor()
        print('Database is opened!')

        cur.execute('DROP TABLE IF EXISTS stocks;')
        cur.execute('''CREATE TABLE stocks
            (date text, account int, description text, increase real, decrease real, accumulate real,
            trans text, symbol text, qty int, price int, tag text)''')

        cur.execute('SELECT * FROM money_transaction')
        records = cur.fetchall()

        stock_records = []
        for record in records:
            account = record[0]
            date = datetime.strptime(record[1], '%d/%m/%Y')
            description = record[2]
            increase = int(record[3].replace(',', ''))
            decrease = int(record[4].replace(',', ''))
            accumulate = int(record[5].replace(',', ''))

            trans = None
            symbol = None
            qty = None
            price = None
            tag = None

            buy_regex = "^Mua (.{3}) (\\d*\\.?\\d*) x (\\d*\\.?\\d*)( .+ )(\\d{2}\\/\\d{2}\\/\\d{4})( : COMMISSION-STOCK$)?"
            buy = re.split(buy_regex, description)

            if len(buy) > 1:
                if buy[6] is not None and buy[6].endswith('COMMISSION-STOCK'):
                    tag = 'fee'
                else:
                    trans = 'BUY'
                    symbol = buy[1]
                    qty = int(buy[2].replace('.', ''))
                    price = int(buy[3].replace('.', ''))
            else:
                sell_regex = "^B.n (.{3}) (\\d*\\.?\\d*) x (\\d*\\.?\\d*)( .+ )(\\d{2}\\/\\d{2}\\/\\d{4})( : COMMISSION-STOCK$)?( : PIT-SELL_STOCK$)?"
                sell = re.split(sell_regex, description)
                if len(sell) > 1:
                    if sell[6] is not None and sell[6].endswith('COMMISSION-STOCK'):
                        tag = 'fee'
                    elif sell[7] is not None and sell[7].endswith('PIT-SELL_STOCK'):
                        tag = 'tax'
                    else:
                        trans = 'SELL'
                        symbol = sell[1]
                        qty = int(sell[2].replace('.', ''))
                        price = int(sell[3].replace('.', ''))

            stock_record = (date.strftime('%Y-%m-%d'), account, description, increase,
                            decrease, accumulate, trans, symbol, qty, price, tag)
            stock_records.append(stock_record)

        cur.executemany('''INSERT INTO stocks (date, account, description, increase, decrease, accumulate, trans, symbol, qty, price, tag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);''', stock_records)
        cur.close()

    except sqlite3.Error as error:
        print('Failed to read data from table', error)
    finally:
        if db_conn:
            db_conn.commit()
            db_conn.close()
            print('Database is closed!')

    print('Fields type correction completed!\n')


def main():
    __version__ = '1.0'

    parser = ArgumentParser(description='Tool for import csv file into SQLite3 database file')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s v{}'.format(__version__))
    parser.add_argument('-f', '--file', help='csv file input')
    parser.add_argument('-db', '--database_file', help='SQLite3 database file')
    parser.add_argument('-ct', '--correct_type', action='store_true', help='Correct fields type in database')

    args = parser.parse_args()

    if args.file and args.database_file:
        import_csv_into_db(args.file, args.database_file)
    elif args.correct_type:
        correct_fields_type(args.database_file)
    else:
        raise RuntimeError('Provide csv and/or db files path')


if __name__ == '__main__':
    main()
