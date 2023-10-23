/**
 *@file: writer.c
 *@description: takes three arguments to copy the string to the file provided by the user
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

#define TOTAL_ARGUMENTS (3)

int main(int argc, char *argv[])
{
	openlog(NULL,0,LOG_USER);
	int result = 0; //success flag
	
	//check if the number of arguments is 3 (writer, filename and string to be written)
	if(argc != TOTAL_ARGUMENTS)
	{
		syslog(LOG_INFO,"Provide the following two arguments\n");
		syslog(LOG_INFO,"Argument 1: File path\n"); 
		syslog(LOG_INFO,"Argument 2: String to be written to the file\n");
		syslog(LOG_ERR,"Invalid number of arguments\n");
		result = 1; //error flag
	}
	
	//if the number of arguments is 3 and if there is no error
	if(result == 0)
	{
		char *filepath=argv[1]; //storing the first argument in filepath (the file in which string is to be written)
		char *writestr=argv[2]; //storing the second argument in writestr (the string to be written)
		
		//open the existing file, if file does not exist then create a new file
		int fd = open(filepath, O_CREAT | O_RDWR | O_TRUNC, 0664);
		
		//check if the file has been created or opened successfully
		if(fd == -1)
		{
			syslog(LOG_ERR,"Failed to create or open a file '%s'\n",filepath);
			result = 1; //error flag
		}
		
		//if file is created or opened successfully
		if(result == 0)
		{
			syslog(LOG_DEBUG, "File '%s' opened/created successfully\n", filepath);

			//write the string to the file that is created or opened
			ssize_t nr = write(fd, writestr, strlen(writestr));
			
			//if string cannot be written to the file
			if(nr == -1)
			{
				syslog(LOG_ERR, "Failed to write the string to file\n");
				result = 1; //error flag
			}

			//if string can be written to the file
			else if(nr == strlen(writestr))
			{
				syslog(LOG_DEBUG, "Writing the string to the file\n");
				result = 0; //success flag
			}
			
			//checking if the file descriptor is closed successfully
			if(close(fd) == 0)
			{
				syslog(LOG_DEBUG, "File closed successfully\n");
			}
		}
	}
	return result;
}
