#!/bin/sh
# Tester script for assignment 1 and assignment 2
# Modified for assignment 4
# Author: Siddhant Jajoo

set -e
set -u

NUMFILES=10
WRITESTR=AELD_IS_FUN
WRITEDIR=/tmp/aeld-data
OUTPUTDIR=/tmp/assignment4-result.txt
CONFDIR=/etc/finder-app/conf
username=$(cat $CONFDIR/username.txt)

# Handling command-line arguments with 3 parameters logic
if [ $# -lt 3 ]
then
    echo "Using default value ${WRITESTR} for string to write"
    if [ $# -lt 1 ]
    then
        echo "Using default value ${NUMFILES} for number of files to write"
    else
        NUMFILES=$1
    fi    
else
    NUMFILES=$1
    WRITESTR=$2
    WRITEDIR=/tmp/aeld-data/$3
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

# Remove the directory if it exists and create it again
rm -rf "${WRITEDIR}"

# Create WRITEDIR if assignment is not assignment1
assignment=$(cat $CONFDIR/assignment.txt)

if [ $assignment != 'assignment1' ]
then
    mkdir -p "$WRITEDIR"

    # The WRITEDIR is in quotes because if the directory path consists of spaces, 
    # then variable substitution will consider it as multiple arguments.
    # The quotes signify that the entire string in WRITEDIR is a single string.
    # This issue can also be resolved by using double square brackets i.e [[ ]] instead of using quotes.
    if [ -d "$WRITEDIR" ]
    then
        echo "$WRITEDIR created"
    else
        exit 1
    fi
fi

# echo "Removing the old writer utility and compiling as a native application"
# make clean
# make

# Write the files using the writer utility from the PATH
for i in $( seq 1 $NUMFILES )
do

    writer "$WRITEDIR/${username}$i.txt" "$WRITESTR"
done

# Run the finder script using the files created and capture the output.

OUTPUTSTRING=$(finder.sh "$WRITEDIR" "$WRITESTR")

# Clean up the temporary directory
rm -rf "$WRITEDIR"

# Check if the output matches the expected string
set +e
echo ${OUTPUTSTRING} | grep "${MATCHSTR}"
if [ $? -eq 0 ]; then
    echo "success"
    # Write the output of finder command to /tmp/assignment4-result.txt
    echo ${OUTPUTSTRING} > $OUTPUTDIR
    if [ $? -eq 1 ]; then
        echo "ERROR: writing output to $OUTPUTDIR"
        exit 1
    else
        echo "Written output to $OUTPUTDIR successfully"
    fi
    exit 0
else
    echo "failed: expected ${MATCHSTR} in ${OUTPUTSTRING} but instead found"
    exit 1
fi

