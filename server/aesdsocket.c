/**********************************
 * File Name: aesdsocket.c
 * Author: Chandan Mohanta
 * References: lecture and slides
 **********************************/

/* Header files */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include "queue.h"
#include "../aesd-char-driver/aesd_ioctl.h"

/* Configuration and Macro Definitions */
#define SERVER_PORT            "9000"
#define USE_AESD_CHAR_DEVICE   (1)
#if (USE_AESD_CHAR_DEVICE == 0)
    #define DATA_FILE_PATH     "/var/tmp/aesdsocketdata"
#elif (USE_AESD_CHAR_DEVICE == 1)
    #define DATA_FILE_PATH     "/dev/aesdchar"
#endif

#define BUFFER_LENGTH          1024
#define SUCCESS                0
#define FAILURE               -1
#define TIMESTAMP_INTERVAL     10
#define MATCHED_INPUTS_COUNT   2

/* Global Variables */
int shutdown_flag = 0;
int daemon_mode_enabled = 0;
int sock_fd;
char client_ip[INET_ADDRSTRLEN];

/* Thread structure using queue.h */
typedef struct socket_thread {
    pthread_t thread_id;
    int client_socket_fd;
    bool thread_complete;
    pthread_mutex_t *thread_mutex;
    SLIST_ENTRY(socket_thread) node_count;
} socket_thread_t;

/* Forward Declarations of Functions */
void signal_handler(int signo);
void close_n_exit(void);
int run_as_daemon_func();
void *timestamp_thread(void *thread_node);
void *data_thread(void *thread_node);


/*  
 * Timestamp Thread Function
 */
#if (USE_AESD_CHAR_DEVICE == 0)
void *timestamp_thread(void *thread_node)
{
    socket_thread_t *node = NULL;
    int status = FAILURE;
    int file_fd = -1;
    struct timespec time_period;
    char output[BUFFER_LENGTH] = {0};
    time_t curr_time;
    struct tm *tm_time;
    int written_bytes = 0;

    if (thread_node == NULL) {
        return NULL;
    }

    node = (socket_thread_t *)thread_node;

    while (!shutdown_flag) {
        if (clock_gettime(CLOCK_MONOTONIC, &time_period) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to get time");
            status = FAILURE;
            goto exit_timestamp;
        }

        time_period.tv_sec += TIMESTAMP_INTERVAL;

        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time_period, NULL) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to sleep for timestamp interval");
            status = FAILURE;
            goto exit_timestamp;
        }

        curr_time = time(NULL);
        if (curr_time == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to get current time");
            status = FAILURE;
            goto exit_timestamp;
        }

        tm_time = localtime(&curr_time);
        if (tm_time == NULL) {
            syslog(LOG_ERR, "ERROR: Failed to parse current time");
            status = FAILURE;
            goto exit_timestamp;
        }

        if (strftime(output, sizeof(output), "timestamp: %Y %B %d, %H:%M:%S\n", tm_time) == SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to format timestamp string");
            status = FAILURE;
            goto exit_timestamp;
        }

        file_fd = open(DATA_FILE_PATH, O_CREAT|O_RDWR|O_APPEND, 
                       S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
        if (file_fd == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to open data file for timestamp");
            status = FAILURE;
            goto exit_timestamp;
        }

        if (pthread_mutex_lock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to lock mutex for timestamp write");
            status = FAILURE;
            goto exit_timestamp;
        }

        /* Write the timestamp data */
        written_bytes = (int)write(file_fd, output, strlen(output));
        if (written_bytes != (int)strlen(output)) {
            syslog(LOG_ERR, "ERROR: Failed to write timestamp to file");
            status = FAILURE;
            pthread_mutex_unlock(node->thread_mutex);
            goto exit_timestamp;
        }

        if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to unlock mutex after timestamp write");
            status = FAILURE;
            goto exit_timestamp;
        }

        status = SUCCESS;
        close(file_fd);
    }

exit_timestamp:
    if (status == FAILURE) {
        node->thread_complete = false;
    } else {
        node->thread_complete = true;
    }
    return thread_node;
}
#endif


/*
 * Data Thread Function
 */
void *data_thread(void *thread_node)
{
    int recv_bytes = 0;
    char buffer[BUFFER_LENGTH] = {0};
    bool packet_complete = false;
    int written_bytes = 0;
    socket_thread_t *node = NULL;
    int status = FAILURE;
    int file_fd = -1;

#if (USE_AESD_CHAR_DEVICE == 1)
    const char *ioctl_str = "AESDCHAR_IOCSEEKTO:";
#endif

    if (thread_node == NULL) {
        return NULL;
    }

    node = (socket_thread_t *)thread_node;

    file_fd = open(DATA_FILE_PATH, O_CREAT|O_RDWR|O_APPEND, 
                   S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    if (file_fd == FAILURE) {
        syslog(LOG_ERR, "ERROR: Failed to open data file");
        status = FAILURE;
        goto exit_data;
    }

    /* Receive data until newline found */
    do {
        memset(buffer, 0, BUFFER_LENGTH);
        recv_bytes = (int)recv(node->client_socket_fd, buffer, BUFFER_LENGTH, 0);
        if (recv_bytes == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to receive data from client");
            status = FAILURE;
            goto exit_data;
        }

#if (USE_AESD_CHAR_DEVICE == 1)
        /* Check for ioctl seek command */
        if (SUCCESS == strncmp(buffer, ioctl_str, strlen(ioctl_str))) {
            struct aesd_seekto seek_info;
            if (MATCHED_INPUTS_COUNT != sscanf(buffer, "AESDCHAR_IOCSEEKTO:%d,%d",
                                               &seek_info.write_cmd,
                                               &seek_info.write_cmd_offset))
            {
                syslog(LOG_ERR, "ERROR: Failed to parse ioctl arguments");
            }
            else
            {
                if(SUCCESS != ioctl(file_fd, AESDCHAR_IOCSEEKTO, &seek_info))
                {
                    syslog(LOG_ERR, "ERROR: ioctl seek failed");
                }
            }
           
            /* After performing ioctl, jump to read and send phase */
            goto read_data;
        }
#endif

        if (pthread_mutex_lock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to lock mutex for data write");
            status = FAILURE;
            goto exit_data;
        }

        written_bytes = (int)write(file_fd, buffer, (size_t)recv_bytes);
        if (written_bytes != recv_bytes) {
            syslog(LOG_ERR, "ERROR: Failed to write received data");
            status = FAILURE;
            pthread_mutex_unlock(node->thread_mutex);
            goto exit_data;
        }

        if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to unlock mutex after data write");
            status = FAILURE;
            goto exit_data;
        }

        if (memchr(buffer, '\n', (size_t)recv_bytes) != NULL) {
            packet_complete = true;
        }

    } while (!packet_complete);

    /* Close after writing */
    close(file_fd);

#if (USE_AESD_CHAR_DEVICE == 0)
    file_fd = open(DATA_FILE_PATH, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
    if (FAILURE == file_fd) {
        syslog(LOG_ERR, "ERROR: Failed to open file in read mode");
        status = FAILURE;
        goto exit_data;
    }
#else
    /* For device, just set offset to start if needed */
    lseek(file_fd, 0, SEEK_SET);
#endif

read_data:
    {
        /* Read entire file/device and send back */
        int read_bytes = 0;
        int send_bytes = 0;
        do {
            memset(buffer, 0, BUFFER_LENGTH);
            read_bytes = (int)read(file_fd, buffer, BUFFER_LENGTH);
            if (read_bytes == -1) {
                syslog(LOG_ERR, "ERROR: Failed to read from file/device");
                status = FAILURE;
                goto exit_data;
            }

            if (read_bytes > 0) {
                send_bytes = (int)send(node->client_socket_fd, buffer, (size_t)read_bytes, 0);
                if (send_bytes != read_bytes) {
                    syslog(LOG_ERR, "ERROR: Failed to send data back to client");
                    status = FAILURE;
                    goto exit_data;
                }
                status = SUCCESS;
            }
        } while (read_bytes > 0);
    }

exit_data:
    if (file_fd != -1) {
        close(file_fd);
    }

    if (close(node->client_socket_fd) == SUCCESS) {
        syslog(LOG_INFO, "Closed connection from %s", client_ip);
    }

    node->thread_complete = (status == FAILURE) ? false : true;
    return thread_node;
}


/*
 * Signal Handler
 */
void signal_handler(int signo)
{
    if ((signo == SIGINT) || (signo == SIGTERM)) {
        shutdown_flag = 1;
        syslog(LOG_DEBUG, "Caught signal, initiating shutdown");
    }
    printf("FOUND SIGNAL!!!!!!!\n");
}


/*
 * Close and Exit
 */
void close_n_exit(void)
{
    if (sock_fd >= 0) {
        syslog(LOG_INFO, "Closing socket");
        close(sock_fd);
        syslog(LOG_INFO, "Socket closed");
    }

#if (USE_AESD_CHAR_DEVICE == 0)
    remove(DATA_FILE_PATH);
#endif

    syslog(LOG_INFO, "Closing syslog");
    closelog();
}


/*
 * Forks and runs as a daemon.
 */
int run_as_daemon_func() 
{
    pid_t pid, sid;

    fflush(stdout);
    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR, "ERROR: Fork failed");
        return FAILURE;
    }
    else if (pid > 0) {
        syslog(LOG_INFO, "Terminating parent after fork");
        exit(SUCCESS);
    }
    else if (pid == 0) {
        syslog(LOG_INFO, "Child process running as daemon");
        sid = setsid();
        if (sid < 0) {
            syslog(LOG_ERR, "ERROR: setsid failed");
            return FAILURE;
        }

        if ((chdir("/")) < 0) {
            syslog(LOG_ERR, "ERROR: chdir failed");
            return FAILURE;
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        int fd = open("/dev/null", O_RDWR);
        if (fd == -1) {
            syslog(LOG_ERR, "ERROR: open /dev/null failed");
            close(fd);
            return FAILURE;       
        }

        if (dup2(fd, STDIN_FILENO)  == -1) {
            syslog(LOG_ERR, "ERROR: dup2 stdin");
            close(fd);
            return FAILURE;    
        }
        if (dup2(fd, STDOUT_FILENO)  == -1) {
            syslog(LOG_ERR, "ERROR: dup2 stdout");
            close(fd);
            return FAILURE;    
        }
        if (dup2(fd, STDERR_FILENO)  == -1) {
            syslog(LOG_ERR, "ERROR: dup2 stderr");
            close(fd);
            return FAILURE;    
        }
        close(fd);
    }

    return SUCCESS;	
}


/*
 * Main Function
 */
int main(int argc, char *argv[])
{
    int status = SUCCESS;
    socket_thread_t *data_ptr = NULL;
    socket_thread_t *data_ptr_temp = NULL;
    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

    openlog(NULL, 0, LOG_USER);

    /* Check if daemon mode requested */
    if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
        printf("RUNNING DAEMON\n");
        daemon_mode_enabled = 1;
        syslog(LOG_INFO, "Running in daemon mode");
    }

    printf("running aesd socket\n");

    /* Register signals */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;

    if (sigaction(SIGINT, &sa, NULL) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: SIGINT registration failed");
        return FAILURE;
    }
    if (sigaction(SIGTERM, &sa, NULL) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: SIGTERM registration failed");
        return FAILURE;
    }
    syslog(LOG_INFO, "Signal handlers registered");

    SLIST_HEAD(socket_head, socket_thread) head;
    SLIST_INIT(&head);

    /* Create socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == FAILURE) {
        syslog(LOG_ERR, "ERROR: Failed to create socket");
        return FAILURE;
    }
    syslog(LOG_INFO, "Socket created successfully");

    /* Setup address info */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *server_addr_info = NULL;
    if (getaddrinfo(NULL, SERVER_PORT, &hints, &server_addr_info) != 0) {
        syslog(LOG_ERR, "ERROR: getaddrinfo failed");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Address obtained from getaddrinfo");

    int reuse_opt = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_opt, sizeof(int)) == FAILURE) {
        syslog(LOG_ERR, "ERROR: setsockopt failed");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Port reuse option set");

    if (bind(sock_fd, server_addr_info->ai_addr, server_addr_info->ai_addrlen) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: bind failed");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Bind successful");

    if (server_addr_info != NULL) {
        freeaddrinfo(server_addr_info);
        syslog(LOG_INFO, "Freed server address info");
    }

    if (daemon_mode_enabled) {
        syslog(LOG_INFO, "Running as daemon");
        if(run_as_daemon_func() != SUCCESS) {
            syslog(LOG_ERR, "ERROR: daemonization failed");
            status = FAILURE;
            goto main_exit;
        }
    }

    if (listen(sock_fd, 10) == -1) {
        syslog(LOG_ERR, "ERROR: listen failed");
        status = FAILURE;
        goto main_exit;
    }

#if (USE_AESD_CHAR_DEVICE == 0)
    /* If not using char device, spawn timestamp thread */
    data_ptr = (socket_thread_t *)malloc(sizeof(socket_thread_t));
    if (data_ptr == NULL) {
        syslog(LOG_ERR, "ERROR: malloc failed for timestamp thread");
        status = FAILURE;
        goto main_exit;
    }

    data_ptr->thread_complete = false;
    data_ptr->thread_mutex = &file_mutex;

    if (pthread_create(&data_ptr->thread_id, NULL, timestamp_thread, data_ptr) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: timestamp thread creation failed");
        free(data_ptr);
        data_ptr = NULL;
        status = FAILURE;
        goto main_exit;
    }
    SLIST_INSERT_HEAD(&head, data_ptr, node_count);
#endif

    
    while(!shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int accepted_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (accepted_fd == FAILURE) {
            syslog(LOG_ERR, "ERROR: accept failed");
        } else {
            syslog(LOG_INFO, "Connection accepted");

            if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
                syslog(LOG_ERR, "ERROR: inet_ntop failed to get client IP");
            }
            syslog(LOG_INFO, "Client IP: %s", client_ip);

            data_ptr = (socket_thread_t *)malloc(sizeof(socket_thread_t));
            if (data_ptr == NULL) {
                syslog(LOG_ERR, "ERROR: malloc failed for connection thread");
                status = FAILURE;
                goto main_exit;
            }

            data_ptr->client_socket_fd = accepted_fd;
            data_ptr->thread_complete = false;
            data_ptr->thread_mutex = &file_mutex;

            if (SUCCESS != pthread_create(&data_ptr->thread_id, NULL, data_thread, data_ptr)) {
                syslog(LOG_ERR, "ERROR: connection thread creation failed");
                free(data_ptr);
                data_ptr = NULL;
                status = FAILURE;
                goto main_exit;
            }
            SLIST_INSERT_HEAD(&head, data_ptr, node_count);
        }

        /* Cleanup finished threads */
        data_ptr = NULL;
        SLIST_FOREACH_SAFE(data_ptr, &head, node_count, data_ptr_temp) {
            if (data_ptr->thread_complete == true) {
                pthread_join(data_ptr->thread_id, NULL);
                SLIST_REMOVE(&head, data_ptr, socket_thread, node_count);
                free(data_ptr);
                data_ptr = NULL;
            }
        }
    }

main_exit:
    close_n_exit();

    /* Join any remaining threads before exiting */
    while (!SLIST_EMPTY(&head)) {
        data_ptr = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, node_count);
        pthread_join(data_ptr->thread_id, NULL);
        free(data_ptr);
        data_ptr = NULL;
    }

    pthread_mutex_destroy(&file_mutex);
    printf("EXITING PROCESS\n");
    return status;
}
