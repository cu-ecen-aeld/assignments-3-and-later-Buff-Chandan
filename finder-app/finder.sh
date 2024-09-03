#!/bin/bash

#author: Chandan Mohanta

#file: finder.sh

#description: Shell script finder-app/finder.sh as described below:
# Accepts the following runtime arguments: the first argument is a path to a directory on the filesystem, referred to below as filesdir; the second # argument is a text string which will be searched within these files, referred to below as searchstr
# Exits with return value 1 error and print statements if any of the parameters above were not specified
# Exits with return value 1 error and print statements if filesdir does not represent a directory on the filesystem
# Prints a message "The number of files are X and the number of matching lines are Y" where X is the number of files in the directory and all #subdirectories and Y is the number of matching lines found in respective files, where a matching line refers to a line which contains searchstr (and may also contain additional content).

#reference: geeksforgeeks, stackoverflow, w3schools, 
# youtube channel: freecodecamp, M Prasad, Kunal Kushwaha, CodingWithMosh

# Accepting 1st arg
filesdir=$1
#Accepting 2nd arg
searchstr=$2

#verifying number of args
if [ $# -ne 2 ]
then
	echo "ERROR: Improper number of args"
	
	#exit with value 1 error
	exit 1
fi

#verifying existence of 'filesdir' 
if [ ! -d "$filesdir" ]
then
	echo "$filesdir file does not exis"
	##exit with value 1 error
	exit 1
else
	#storing num of files in var 'num_file'
	num_file=$(find "$filesdir" -type f | wc -l)
	#storing number of matching lines var 'num_line'
	num_line=$(grep -r "$searchstr" "$filesdir" | wc -l)
	
	echo "The number of files are $num_file and the number of matching lines are $num_line"
	
	exit 0
fi

#end
