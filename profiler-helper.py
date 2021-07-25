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
            date = datetime.strptime(record[1], '%d/%m/%Y').strftime('%Y-%m-%d')
            description = record[2]
            increase = int(record[3].replace(',', ''))
            decrease = int(record[4].replace(',', ''))
            accumulate = int(record[5].replace(',', ''))
            [trans, symbol, qty, price, tag] = buy_sell_description_parser(description)
            stock_record = (date, account, description, increase, decrease, accumulate, trans, symbol, qty, price, tag)
            stock_records.append(stock_record)

        cur.executemany('''INSERT INTO stocks (date, account, description, increase, decrease, accumulate, trans, symbol, qty, price, tag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);''', stock_records)

        cur.execute('''UPDATE stocks SET tag='deposit' WHERE (stocks.description LIKE '%Chuyen tien vao tai khoan%'
            OR stocks.description LIKE '%NOP TIEN%') AND stocks.increase > 0;''')
        cur.execute("UPDATE stocks SET tag='interest' WHERE stocks.description LIKE 'L_i ti_n g_i%' AND stocks.increase > 0;")
        cur.execute("UPDATE stocks SET tag='dividend' WHERE stocks.description LIKE 'Thanh to_n c_ t_c %' AND stocks.increase > 0;")

        cur.execute("UPDATE stocks SET tag='withdraw' WHERE stocks.description LIKE '%Tat toan%' AND stocks.decrease > 0;")
        cur.execute(
            "UPDATE stocks SET tag='tax-interest' WHERE stocks.description LIKE 'Thu_ l_i ti_n g_i%' AND stocks.decrease > 0;")
        cur.execute("UPDATE stocks SET tag='fee-other' WHERE stocks.description LIKE 'Thu ph_ %' AND stocks.decrease > 0;")

        cur.execute(
            "UPDATE stocks SET tag='margin' WHERE stocks.description LIKE 'Gi_i ng_n GDKQ %' OR stocks.description LIKE 'Thu n_ GDKQ %';")
        cur.execute("UPDATE stocks SET tag='margin-interest' WHERE stocks.description LIKE 'L_i vay GDKQ %' AND stocks.decrease > 0;")

        cur.execute("UPDATE stocks SET tag='ignore' WHERE stocks.description LIKE '%CKNB%';")
        cur.close()

    except sqlite3.Error as error:
        print('Failed to read data from table', error)
    finally:
        if db_conn:
            db_conn.commit()
            db_conn.close()
            print('Database is closed!')

    print('Fields type correction completed!\n')


def buy_sell_description_parser(description):
    buy_regex = "^Mua (.{3}) (\\d*\\.?\\d*) x (\\d*\\.?\\d*)( .+ )(\\d{2}\\/\\d{2}\\/\\d{4})( : COMMISSION-STOCK$)?"
    sell_regex = "^B.n (.{3}) (\\d*\\.?\\d*) x (\\d*\\.?\\d*)( .+ )(\\d{2}\\/\\d{2}\\/\\d{4})( : COMMISSION-STOCK$)?( : PIT-SELL_STOCK$)?"

    trans = None
    symbol = None
    qty = None
    price = None
    tag = None

    buy = re.split(buy_regex, description)
    if len(buy) > 1:
        if buy[6] is not None and buy[6].endswith('COMMISSION-STOCK'):
            tag = 'fee'
        else:
            trans = 'BUY'
            symbol = buy[1]
            qty = int(buy[2].replace('.', ''))
            price = int(buy[3].replace('.', ''))
            tag = trans

        return [trans, symbol, qty, price, tag]

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
            tag = trans

        return [trans, symbol, qty, price, tag]

    return [trans, symbol, qty, price, tag]


def encrypt_db(db_file, pub_key):
    pass


def decrypt_db(db_file, pri_key):
    pass


def main():
    __version__ = '1.0'

    parser = ArgumentParser(description='Helper tool for Stock Trading Profiler project')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s v{}'.format(__version__))
    parser.add_argument('-a', '--append', action='store_true', help='import csv file into db file')
    parser.add_argument('-f', '--file', help='csv file input')
    parser.add_argument('-db', '--database_file', help='sqlite3 database file')
    parser.add_argument('-ct', '--correct_type', action='store_true', help='correct fields type in database')
    parser.add_argument('-enc', '--encrypt_database', action='store_true', help='encrypt plaintext database file')
    parser.add_argument('-pubkey', '--public_Key', help='public key (PEM format) for encryption')
    parser.add_argument('-dec', '--decrypt_database', action='store_true', help='decrypt cipher database file')
    parser.add_argument('-prikey', '--private_Key', help='private key (PEM format) for decryption')

    args = parser.parse_args()

    if args.append and args.file and args.database_file:
        import_csv_into_db(args.file, args.database_file)

    elif args.correct_type and args.database_file:
        correct_fields_type(args.database_file)

    elif args.encrypt_database and args.public_Key:
        encrypt_db(args.encrypt_database, args.public_Key)

    elif args.decrypt_database and args.private_Key:
        decrypt_db(args.decrypt_database, args.private_Key)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
