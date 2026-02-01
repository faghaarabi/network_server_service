On macOS:
brew install gdbm



On Linux:
sudo apt install libgdbm-dev

Build DB test:

cc -Iinclude -o db_test src/db_test.c src/user_db.c
./db_test

Run:
./db_test



