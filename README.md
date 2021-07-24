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
import-csv-to-db -f file.csv -o data.db
````

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
