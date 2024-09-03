#author: Chandan Mohanta
#file: writer.sh

#reference: geeksforgeeks, stackoverflow, w3schools, 
# youtube channel: freecodecamp, M Prasad, Kunal Kushwaha, CodingWithMosh


#!/bin/bash

# Check if exactly two arguments are provided
[ $# -ne 2 ] && { echo "Error: Two arguments required: <writefile> <writestr>"; exit 1; }

# Assign arguments to variables
writefile=$1
writestr=$2

# Create the directory path if it doesn't exist
mkdir -p "$(dirname "$writefile")" || { echo "Failed to create the directory structure."; exit 1; }

# Write the string to the file, overwrite if exists
echo "$writestr" > "$writefile" || { echo "Unable to write to the specified file."; exit 1; }

# Confirmation message
echo "File created: $writefile with content: $writestr"

