this python codes searches very fast folders for duplicates based on file size, hash codes and stores log and csv output in a store folder.
developed and tested on python 3.14 on Windows.

prerequisites installed python 3.14

Forked from https://gist.github.com/tfeldmann/fc875e6630d11f2256e746f67a09c1ae
which is based on https://stackoverflow.com/a/36113168/300783 and

updated original script to contain:
1. error logging
2. storing output in csv file with file,foldername, duplicates details
3. commandline 
4. output folder 
5. option to rename duplicates to delete them afterwards.

Usage:
    duplicates.py <folder> [<folder> ...]
                  [--store-dir STORE]
                  [--hash {sha1,sha256,blake2b}]
                  [--chunk-size BYTES]
                  [--log-level {DEBUG,INFO,WARNING,ERROR}]
                  [--rename-duplicates]
                  [--prefix PREFIX]
                  [--dry-run]
                  [--keep-strategy {first,mtime_oldest,mtime_newest}]

Defaults:
- NO renaming unless --rename-duplicates is provided.
- CSV filenames are timestamped to avoid overwriting previous results.

Outputs:
- store/duplicates.log
- store/duplicates-YYYY-MM-DD_HH-MM-SS.csv

Sample call under windows
python .\duplicates-v1.1d.py '\\networkdrive\folder with spaces\files' --store-dir C:\working\store --rename-duplicates  --dry-run --prefix __del__ --log-level DEBUG
