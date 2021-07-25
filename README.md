# Python handly tools

Helper tools for stock market profiler project

## Convert xls file to csv

Convert one file

```bash
convert-xls-to-csv.py -f file00.xls
```

Convert multiple files

```bash
convert-xls-to-csv.py -f file01.xls file02.xls
```

## Import csv file into db file (SQLite3 database)

Import one csv file into database file. If the db file not available, a new output file will be created.

```bash
profiler-helper.py -a -f file.csv -db data.db
````

Create new table with correct fields type and extract more handle fields for future use
```bash
profiler-helper.py -ct -db data.db
```

## Database encryption and decryption

To encrypt the database file with a public key:
```bash
profiler-helper.py -enc -db data.db -k pubKey.pem
```

To decrypt the database file with a private key:
```bash
profiler-helper.py -dec -db cipher.db -k privKey.pem
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
