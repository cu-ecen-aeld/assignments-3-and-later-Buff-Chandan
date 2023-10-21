/*@Modified by: Chandan Mohanta
 *@filename: systemcalls.c
 *@brief: Assignment 3 
*/

#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "fcntl.h"
#include "systemcalls.h"
#include "sys/wait.h"
#include "sys/types.h"

/*
 *
 * @param cmd the command to execute with system()
 * @return true if the commands in ... with arguments @param arguments were executed 
 *   successfully using the system() call, false if an error occurred, 
 *   either in invocation of the system() command, or if a non-zero return 
 *   value was returned by the command issued in @param.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success 
 *   or false() if it returned a failure
*/
    int status;
    status = system(cmd);
    if(status == -1)
    	printf("Error: system error");

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the 
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *   
*/
    pid_t pid;

    pid = fork();

    //check for fork() errors
    if(pid == -1)
    {
	    printf("ERROR: fork error");
    }	    
    //created the child process
    else if(!pid)
    {
    	    printf("Child process was created\n");
	    int status;
	    status = execv(command[0],command);
	    if(status==-1)
	    {
		    printf("ERROR: execv");
		    exit(EXIT_FAILURE);
	    }      	    
	    
    }
    
    //waiting for child process to be terminated
    // ref: LSP book, Launching and waiting for new process 
    
    else
    {
    int w_status;
    pid_t waiting_state;

    waiting_state = waitpid(0,&w_status,0);
    if(waiting_state==-1)
    {
	    printf("ERROR: waitpid");
	    return false;
    }	    
    else
    {
	    printf("pid=%d\n",waiting_state);

	    if(WIFEXITED (w_status))
	    {
		    printf("safe exit status=%d\n",WEXITSTATUS (w_status));
		    if(WEXITSTATUS(w_status) == EXIT_SUCCESS)
		    {
			    return true;
		    }
		    else
		    {
			    return false;
		    }
	    }      		
	    if(WIFSIGNALED (w_status))
	    {
		    printf("Killed by signal=%d%s\n",WTERMSIG (w_status),WCOREDUMP (w_status) ? " (dumped core)" : "");
		    return false;
	    }	   
	    
    }
    	
    }
    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.  
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/

bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *   
*/


    int child_pid, status;
    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0) 
    {
	    printf("ERROR: open"); 
	    abort();
    }
    switch (child_pid = fork()) {
    	case -1: printf("ERROR: fork"); 
		 abort();
    	case 0:
    		if (dup2(fd, 1) < 0) 
		{ 
			printf("ERROR: dup2"); 
			abort();
	       	}
    		close(fd);
    		status = execv(command[0], command);
	       	if(status==-1)
		{
			printf("ERROR: execvp");
	       		abort();
		}
  	default:
    		close(fd);
    		
    /* copy what parent process do */
    
    int w_status;
    pid_t waiting_state;

    waiting_state = waitpid(0,&w_status,0);
    if(waiting_state==-1)
    {
	    printf("ERROR: waitpid");
	    return false;
    }	    
    else
    {
	    printf("pid=%d\n",waiting_state);

	    if(WIFEXITED (w_status))
	    {
		    printf("safe exit status=%d\n",WEXITSTATUS (w_status));
		    if(WEXITSTATUS(w_status) == EXIT_SUCCESS)
		    {
			    return true;
		    }
		    else
		    {
			    return false;
		    }
	    }      		
	    if(WIFSIGNALED (w_status))
	    {
		    printf("Killed by signal=%d%s\n",WTERMSIG (w_status),WCOREDUMP (w_status) ? " (dumped core)" : "");
		    return false;
	    }	   
	    
    }
 
    }

    close(fd);
    va_end(args);
    
    return true;
}		

