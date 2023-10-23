#!/bin/sh

#file: finder.sh
#

#1st argument as filesdir
filesdir=$1
#2nd argument as searchstr
searchstr=$2

#checking if the number of arguments is 2
if [ $# -ne 2 ]
then
	echo "ERROR: Invalid number of arguments"
	echo "Total number of arguments should be 2"
	echo "The order of arguments should be:"
	echo "1) Path to a directory on the filesystem."
	echo "2) String to be searched within these files."
	#exit with return value 1
	exit 1
fi

#checking if 'filesdir' is the existing directory
if [ ! -d "$filesdir" ]
then
	echo "$filesdir does not represent a directory on the file system."
	#exit with return value 1
	exit 1
else
	#storing the number of files in the directory an all subdirectories in variable 'no_of_files'
	no_of_files=$(find "$filesdir" -type f | wc -l)
	#storing the number of matching lines found in respective files in variable 'no_of_lines'
	no_of_lines=$(grep -r "$searchstr" "$filesdir" | wc -l)
	
	echo "The number of files are $no_of_files and the number of matching lines are $no_of_lines"
	
	exit 0
fi

#end
