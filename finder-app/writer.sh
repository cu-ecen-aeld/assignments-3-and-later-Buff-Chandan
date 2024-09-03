#!/bin/bash

# Author: Chandan Mohanta
# Filename: writer.sh
# Check for error if there are invalid arguments

# shell script finder-app/writer.sh as described below:
# Accepts the following arguments: the first argument is a full path to a file (including filename) on the filesystem, referred to #below as writefile; the second argument is a text string which will be written within this file, referred to below as writestr
# Exits with value 1 error and print statements if any of the arguments above were not specified
# Creates a new file with name and path writefile with content writestr, overwriting any existing file and creating the path if it  doesn’t exist. Exits with value 1 and error print statement if the file could not be created.

#reference: geeksforgeeks, stackoverflow, w3schools, 
# youtube channel: freecodecamp, M Prasad, Kunal Kushwaha, CodingWithMosh


#checking num of args
if [ ! $# -eq 2 ]
then 

	echo "unspecified num of parameters"
	
	#exit with value 1 error
	exit 1

fi


# Accepting 1st arg
writefile=$1

# Accepting 2nd arg
writestr=$2


# Creating path for the dir
mkdir -p $(dirname $writefile)

# Creating new file in the dir
touch $writefile 

# Verifying is file creared
if [[ -f $writefile ]]
then
	echo "$writestr" > "$writefile"
	#exit with value 0
	exit 0
else
	echo "File Not Created"
	#exit with value 1 error
	exit 1

fi
