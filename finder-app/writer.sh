#!/bin/bash

#file: writer.sh
#

#1st argument as 'writefile'
writefile=$1
#'2nd argument as 'writestr'
writestr=$2

#checking if the number of arguments is 2
if [ $# -ne 2 ]
then
	echo "ERROR: Invalid number of arguments"
	echo "Total number of arguments should be 2"
	echo "The order of arguments should be:"
	echo "1) Full path to a file on the filesystem"
	echo "2) String that will be written within this file"
	#exit with value 1
	exit 1
fi

#checking if the directory already exists
if [ ! -d "${writefile%/*}" ]
then
	#creating a new directory
	mkdir -p "${writefile%/*}"
	#creating a  new file in the directory
	touch $writefile
fi

#copy the content content to writefile
echo $writestr > $writefile

#checking if the file has been created
if [ ! -f "$writefile" ]
then
	echo "File could not be created"
	#exit with value 1
 	exit 1
fi  

#end
