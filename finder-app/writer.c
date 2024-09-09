#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>


#define REQUIRED_ARGS (3)

int main(int argc, char *argv[])
{
    // Initialize syslog
    openlog(NULL, 0, LOG_USER);
    int result = 0; // Success flag

    // Validate the number of arguments
    if (argc != REQUIRED_ARGS)
    {
        syslog(LOG_INFO, "Usage:\n");
        syslog(LOG_INFO, "Argument 1: File path\n");
        syslog(LOG_INFO, "Argument 2: String to write into the file\n");
        syslog(LOG_ERR, "Invalid number of arguments\n");
        return 1; // Return if argument count is incorrect
    }

    // Getting file path and string from the arguments
    const char *filepath = argv[1];
    const char *writestr = argv[2];

    // Open the file and create if it does not exist, truncate if exists
    int fd = open(filepath, O_CREAT | O_RDWR | O_TRUNC, 0664);

    // Handle file open on failure
    if (fd == -1)
    {
        syslog(LOG_ERR, "Failed to open or create file '%s'\n", filepath);
        return 1; // Return if file open failed
    }

    // Log file open on success
    syslog(LOG_DEBUG, "Successfully opened/created file '%s'\n", filepath);

    // Attempting to write the string into the file
    ssize_t bytes_written = write(fd, writestr, strlen(writestr));

    // Handling write failure
    if (bytes_written == -1)
    {
        syslog(LOG_ERR, "Failed to write to file '%s'\n", filepath);
        close(fd);
        return 1;
    }

    // Validate that the entire string was written
    if (bytes_written == (ssize_t)strlen(writestr))
    {
        syslog(LOG_DEBUG, "Successfully wrote the string to file '%s'\n", filepath);
    }

    // Close the file and check for errors
    if (close(fd) == 0)
    {
        syslog(LOG_DEBUG, "File '%s' closed successfully\n", filepath);
    }
    else
    {
        syslog(LOG_ERR, "Error closing file '%s'\n", filepath);
        return 1;
    }

    // Clean up and exit
    return result;
}

