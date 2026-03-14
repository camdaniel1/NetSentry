"""
This file outlines how files in this folder are used.


db.py:

Creates the events.db database specified by DB_PATH, which stores Findings (incidents).
Also stores the connection and initialization of this database.


event_store.py:

Handles data entry and removal from the events.db database. Returned Findings are stored
as FindingRecord type, which is just a Finding with extra fields as stored in the database.

Most useful method is save_finding(), which saves a Finding in the database along with
its file and exact location. This file also contains get methods to return specific database
entries. These are not necessarily used by the pipeline, but rather other files that need
to access database information to do their roles.


models.py:

Creates a type (FindingRecord) for a Finding as it exists in the database. This type
is only used in get methods retrieving from the database.

Also contains the from_row(sqlite3.Row) function to retrieve a FindingRecord from
a specific database row.

"""