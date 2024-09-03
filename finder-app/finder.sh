#author: Chandan Mohanta
#file: finder.sh

#reference: geeksforgeeks, stackoverflow, w3schools, 
# youtube channel: freecodecamp, M Prasad, Kunal Kushwaha, CodingWithMosh

#!/bin/bash

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
