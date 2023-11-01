#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...) 

#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
#define MS_MULTIPLIER 10e3

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    thread_func_args->thread_complete_success = false;
    
    //Sleeping before obtaining lock
    if(usleep(thread_func_args->wait_to_obtain_ms*MS_MULTIPLIER) == -1 )     //return -1 on error
    {
    	ERROR_LOG("usleep error. Error no: %d",errno);
    	return thread_param;
    }
    
    //Make lock
    if( pthread_mutex_lock(thread_func_args->mutex) != 0)     //returns 0 on success
    {
    	ERROR_LOG("mutex lock error. Error no: %d",errno);
    	return thread_param;
    }
    
    //Hold lock
    if (usleep(thread_func_args->wait_to_release_ms*MS_MULTIPLIER) == -1)     //return -1 on error
    {
    	ERROR_LOG("usleep error. Error no: %d",errno);
    	return thread_param;
    }
    
    //Release lock
    if( pthread_mutex_unlock(thread_func_args->mutex) != 0)     //returns 0 on success
    {
    	ERROR_LOG("mutex unlock error. Error no: %d",errno);
    	return thread_param;
    }
    
    //On success
    thread_func_args->thread_complete_success = true;
    return thread_param;
}


/**
* Start a thread which sleeps @param wait_to_obtain_ms number of milliseconds, then obtains the
* mutex in @param mutex, then holds for @param wait_to_release_ms milliseconds, then releases.
* The start_thread_obtaining_mutex function should only start the thread and should not block
* for the thread to complete.
* The start_thread_obtaining_mutex function should use dynamic memory allocation for thread_data
* structure passed into the thread.  The number of threads active should be limited only by the
* amount of available memory.
* The thread started should return a pointer to the thread_data structure when it exits, which can be used
* to free memory as well as to check thread_complete_success for successful exit.
* If a thread was started succesfully @param thread should be filled with the pthread_create thread ID
* coresponding to the thread which was started.
* @return true if the thread could be started, false if a failure occurred.
*/
bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
	openlog("A4", LOG_PID, LOG_USER);
	struct thread_data *thread_func_args = (struct thread_data*)malloc(sizeof(struct thread_data));
	if(thread_func_args == NULL)
	{	
	 // Memory allocation error
	 return false;
	}
	thread_func_args->mutex = mutex;
	thread_func_args->wait_to_obtain_ms = wait_to_obtain_ms;
	thread_func_args->wait_to_release_ms = wait_to_release_ms;
	thread_func_args->thread_complete_success = false;
	
	int pthread_create_return = pthread_create(thread,NULL,threadfunc, (void *) thread_func_args);
	
	if(pthread_create_return != 0)
	{
		syslog(LOG_ERR,"Failed to create thread. Error no: %d",errno);
		ERROR_LOG("Failed to create thread. Error no: %d",errno);
		closelog();
		free(thread_func_args);
		return false;
	}
	else
	{
		syslog(LOG_INFO,"Successfully created thread");
		DEBUG_LOG("Successfully created thread");
		closelog();
		return true;

	}
	
    return false;
}

