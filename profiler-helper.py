#!/usr/bin/env python3

from argparse import ArgumentParser
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from datetime import datetime
from tinyec import ec
from tinyec import registry
import argparse
import csv
import hashlib
import os
import os
import pandas as pd
import re
import secrets
import sqlite3


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
    if not os.path.exists(db_file) or not os.path.exists(pub_key):
        raise RuntimeError('Please provide correct path to db and/or public key')


def aes_256_cbc_encrypt(plain_block, secret):
    secret_key = hashlib.sha256(secret).digest()
    if len(plain_block) % AES.block_size != 0:
        raise RuntimeError('input len', len(plain_block), 'must align with AES.block_size: ', AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plain_block)


def aes_256_gcm_encrypt(plain_block, secret):
    secret_key = hashlib.sha256(secret).digest()
    aes_gcm = AES.new(secret_key, AES.MODE_GCM)
    cipher_text, auth_tag = aes_gcm.encrypt_and_digest(plain_block)
    iv = aes_gcm.nonce
    return auth_tag + cipher_text + iv


def ecc_aes_encrypt(plain_block, pub_key):
    with open(pub_key, 'r') as f:
        ecc_pub_key = ECC.import_key(f.read())

    curve = registry.get_curve('secp256r1')
    pub_key = ec.Point(curve, int(str(ecc_pub_key.pointQ.x)), int(str(ecc_pub_key.pointQ.y)))
    session_priv_key = secrets.randbelow(curve.field.n)
    shared_secret_point = session_priv_key * pub_key

    shasum = hashlib.sha256(int.to_bytes(shared_secret_point.x, 32, 'big'))
    shasum.update(int.to_bytes(shared_secret_point.y, 32, 'big'))
    shared_secret = shasum.digest()
    cipher_block = aes_256_gcm_encrypt(plain_block, shared_secret)

    session_pub_key = session_priv_key * curve.g
    ecc_session_pub_key = ECC.construct(curve='secp256r1', point_x=session_pub_key.x, point_y=session_pub_key.y)
    der = ecc_session_pub_key.export_key(format='DER')
    der_len = len(der).to_bytes(2, byteorder='big')

    return der_len + der + cipher_block


def decrypt_db(cipher_db_file, priv_key):
    if not os.path.exists(cipher_db_file) or not os.path.exists(priv_key):
        raise RuntimeError('Please provide correct path to cipher db and/or private key')


def aes_256_cbc_decrypt(cipher_block, secret):
    secret_key = hashlib.sha256(secret).digest()
    iv = cipher_block[:AES.block_size]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    return cipher.decrypt(cipher_block[AES.block_size:])


def aes_256_gcm_decrypt(cipher_block, secret):
    auth_tag = cipher_block[:AES.block_size]
    cipher_text = cipher_block[AES.block_size:-AES.block_size]
    nonce = cipher_block[-AES.block_size:]
    secret_key = hashlib.sha256(secret).digest()
    aes_gcm = AES.new(secret_key,  AES.MODE_GCM, nonce)
    return aes_gcm.decrypt_and_verify(cipher_text, auth_tag)


def ecc_aes_decrypt(cipher_block, priv_key):
    der_len_size = 2
    der_len = int.from_bytes(cipher_block[:der_len_size], byteorder='big')
    der = cipher_block[der_len_size:(der_len + der_len_size)]
    cipher = cipher_block[(der_len_size + der_len):]

    ecc_ciphertext_pub_key = ECC.import_key(der)
    curve = registry.get_curve('secp256r1')
    ciphertext_pub_key = ec.Point(curve, int(str(ecc_ciphertext_pub_key.pointQ.x)),
                                  int(str(ecc_ciphertext_pub_key.pointQ.y)))

    with open('../Profiler/privKey.pem', 'r') as f:
        ecc_priv_key = ECC.import_key(f.read())
    priv_key = int(str(ecc_priv_key.d))
    shared_secret_point = priv_key * ciphertext_pub_key

    shasum = hashlib.sha256(int.to_bytes(shared_secret_point.x, 32, 'big'))
    shasum.update(int.to_bytes(shared_secret_point.y, 32, 'big'))
    shared_secret = shasum.digest()

    return aes_256_gcm_decrypt(cipher, shared_secret)


def main():
    __version__ = '1.0'

    parser = ArgumentParser(description='Helper tool for Stock Trading Profiler project')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s v{}'.format(__version__))
    parser.add_argument('-a', '--append', action='store_true', help='import csv file into db file')
    parser.add_argument('-f', '--file', help='csv file input')
    parser.add_argument('-db', '--database_file', help='sqlite3 database file')
    parser.add_argument('-ct', '--correct_type', action='store_true', help='correct fields type in database')
    parser.add_argument('-enc', '--encrypt_database', action='store_true', help='encrypt plaintext database file')
    parser.add_argument('-dec', '--decrypt_database', action='store_true', help='decrypt cipher database file')
    parser.add_argument('-k', '--key', help='public key or private key in PEM or DER format')

    args = parser.parse_args()

    if args.append and args.file and args.database_file:
        import_csv_into_db(args.file, args.database_file)

    elif args.correct_type and args.database_file:
        correct_fields_type(args.database_file)

    elif args.encrypt_database and args.database_file and args.key:
        encrypt_db(args.database_file, args.key)

    elif args.decrypt_database and args.database_file and args.key:
        decrypt_db(args.database_file, args.key)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
