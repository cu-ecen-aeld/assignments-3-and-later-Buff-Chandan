#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)


void* threadfunc(void* thread_param) {

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // Convert wait times from milliseconds to seconds
    int time_before_lock = thread_func_args->delay_before_lock_ms / 1000;
    int lock_duration = thread_func_args->hold_mutex_duration_ms / 1000;

    // Sleep for the specified time before attempting to lock the mutex
    sleep(time_before_lock);

    // Lock the mutex
    if (pthread_mutex_lock(thread_func_args->mutex) != 0) {
        ERROR_LOG("Could not implement lock");
        pthread_exit(thread_param);  // Exit the thread if locking fails
    }

    DEBUG_LOG("Mutex locking the thread");

    // Sleep while holding the mutex
    sleep(lock_duration);

    // Unlock the mutex
    if (pthread_mutex_unlock(thread_func_args->mutex) != 0) {
        ERROR_LOG("Failed to release the mutex");
        pthread_exit(thread_param);  // Exit the thread if unlocking fails
    }

    DEBUG_LOG("Mutex unlocked by thread");

    // Indicate that the thread has successfully completed its task
    thread_func_args->thread_complete_success = true;

    // Exit the thread and return the thread data
    pthread_exit(thread_param);
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex, int delay_before_lock_ms, int hold_mutex_duration_ms) {
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     
    struct thread_data* thread_info_data = (struct thread_data*) malloc(sizeof(struct thread_data));
    if (thread_info_data == NULL) {
        ERROR_LOG("Unable to allocate memory for thread_data");
        return false;
    }

    // Initialize thread data with the provided mutex and wait times
    thread_info_data->mutex = mutex;
    thread_info_data->delay_before_lock_ms = delay_before_lock_ms;
    thread_info_data->hold_mutex_duration_ms = hold_mutex_duration_ms;
    thread_info_data->thread_complete_success = false;

    // Create the thread using pthread_create and pass the thread data
    int result = pthread_create(thread, NULL, threadfunc, (void*) thread_info_data);
    if (result != 0) {
        ERROR_LOG("Unable to create the thread");
        free(thread_info_data);  // Free allocated memory if thread creation fails
        return false;
    }

    // Return true if the thread was successfully created
    return true;
}

