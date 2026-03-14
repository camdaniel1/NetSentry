"""
This file details the uses of files in this folder.


custody.py:

This file is used to handle chain of custody in forensic operations.
CUSTODY_LOG_PATH stores a list of CustodyEvents. CustodyEvent stores the
file, hash, timestamp and other necessary data.

record_custody_event() is used to hash the file and append a line to the
custody log recording that hash. If the file is later modified, the hash stored
in the custody log will be different than the file's current hash.
verify_file_integrity(Path) checks that the current file hash matches the last
recorded file hash stored in the log and returns a boolean.

Whenever it's meaningful to record an event (case being closed), the
record_custody_event() should be called to ensure the evidence is no longer
tampered with.


vault.py:

This file handles storage related operations regarding PCAP files. VAULT_DIR
is the location on disc for PCAP files to be stored. list_files() will enumerate
all the files in this directory, oldest first. prune_expired() deletes files in the
vault that are older than DEFAULT_RETENTION_DAYS

This file also contains logic for whether files should rotate as is executed
by pcap_writer.py in its call to get_active_file()

"""

