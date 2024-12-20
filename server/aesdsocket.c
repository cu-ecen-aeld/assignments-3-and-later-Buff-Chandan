/**********************************
 * File Name: aesdsocket.c
 * Author: Chandan Mohanta
 * Subject: Advanced Embedded Systems Design (AESD)
 * References: lecture and slides	
 * Description:
 * Continued for Assignment_6
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
#define RFC2822_FORMAT         "%a, %d %b %Y %H:%M:%S %z"


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
 * This runs periodically (every TIMESTAMP_INTERVAL seconds) to append
 * timestamp data to the output file. Requires a mutex lock for thread-safe
 * file operations.
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
            syslog(LOG_ERR, "ERROR: Failed to sleep for 10 sec");
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
            syslog(LOG_ERR, "ERROR: Failed to fill tm struct");
            status = FAILURE;
            goto exit_timestamp;
        }

        if (strftime(output, sizeof(output), "timestamp: %Y %B %d, %H:%M:%S\n", tm_time) == SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to convert tm into string");
            status = FAILURE;
            goto exit_timestamp;
        }

        file_fd = open(DATA_FILE_PATH, O_CREAT|O_RDWR|O_APPEND, 
                       S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
        if (file_fd == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to create/open file");
            status = FAILURE;
            goto exit_timestamp;
        }

        if (pthread_mutex_lock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to lock mutex");
            status = FAILURE;
            goto exit_timestamp;
        }

        /* Attempt to write the timestamp to the file */
        written_bytes = (int)write(file_fd, output, strlen(output));
        if (written_bytes != (int)strlen(output)) {
            syslog(LOG_ERR, "ERROR: Failed to write timestamp to file");
            status = FAILURE;
            pthread_mutex_unlock(node->thread_mutex);
            goto exit_timestamp;
        }

        if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
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
 * Handles client connections:
 * 1) Receive data until newline is encountered.
 * 2) Write received data into the file.
 * 3) Read entire file and send back to client.
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

    if (thread_node == NULL) {
        return NULL;
    }

    node = (socket_thread_t *)thread_node;

    file_fd = open(DATA_FILE_PATH, O_CREAT|O_RDWR|O_APPEND, 
                   S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    if (file_fd == FAILURE) {
        syslog(LOG_ERR, "ERROR: Failed to create/open file");
        status = FAILURE;
        goto exit_data;
    }

    /* Receive data from client until newline is found */
    do {
        memset(buffer, 0, BUFFER_LENGTH);
        recv_bytes = (int)recv(node->client_socket_fd, buffer, BUFFER_LENGTH, 0);
        if (recv_bytes == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to receive byte from client");
            status = FAILURE;
            goto exit_data;
        }

        if (pthread_mutex_lock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to lock mutex");
            status = FAILURE;
            goto exit_data;
        }

        written_bytes = (int)write(file_fd, buffer, (size_t)recv_bytes);
        if (written_bytes != recv_bytes) {
            syslog(LOG_ERR, "ERROR: Failed to write data");
            status = FAILURE;
            pthread_mutex_unlock(node->thread_mutex);
            goto exit_data;
        }

        if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
            status = FAILURE;
            goto exit_data;
        }

        if (memchr(buffer, '\n', (size_t)recv_bytes) != NULL) {
            packet_complete = true;
        }

    } while (!packet_complete);

    /* Close the file (writing phase done) */
    close(file_fd);
    file_fd = open(DATA_FILE_PATH, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
    if (FAILURE == file_fd) {
        syslog(LOG_ERR, "Error opening %s file: %s", DATA_FILE_PATH, strerror(errno));
        status = FAILURE;
        goto exit_data;
    }

    /* Read the entire file and send it back to the client */
    int read_bytes = 0;
    int send_bytes = 0;
    do {
        memset(buffer, 0, BUFFER_LENGTH);
        read_bytes = (int)read(file_fd, buffer, BUFFER_LENGTH);
        if (read_bytes == -1) {
            syslog(LOG_ERR, "ERROR: Failed to read from file");
            status = FAILURE;
            goto exit_data;
        }
        syslog(LOG_INFO, "read successful is: %d", read_bytes);
        syslog(LOG_INFO, "read successful is: %s", buffer);

        if (read_bytes > 0) {
            send_bytes = (int)send(node->client_socket_fd, buffer, (size_t)read_bytes, 0);
            if (send_bytes != read_bytes) {
                syslog(LOG_ERR, "ERROR: Failed to send bytes to client");
                status = FAILURE;
                goto exit_data;
            }
            status = SUCCESS;
        }
    } while (read_bytes > 0);


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
 * Signal Handler: Handles SIGINT and SIGTERM to signal a shutdown.
 */
void signal_handler(int signo)
{
    if ((signo == SIGINT) || (signo == SIGTERM)) {
        shutdown_flag = 1;
        syslog(LOG_DEBUG, "Caught signal, exiting");
    }
    printf("FOUND SIGNAL!!!!!!!\n");
}


/*
 * Close and Exit:
 * Closes all open sockets, removes file if necessary, and closes syslog.
 */
void close_n_exit(void)
{
    if (sock_fd >= 0) {
        syslog(LOG_INFO, "Closing sock_fd: %d", sock_fd);
        close(sock_fd);
        syslog(LOG_INFO, "Closed sock_fd: %d", sock_fd);
    }

#if (USE_AESD_CHAR_DEVICE == 0)
    remove(DATA_FILE_PATH);
#endif

    syslog(LOG_INFO, "Closing syslog");
    closelog();
}


/*
 * Daemon Mode Function:
 * Forks the current process and sets it to run as a daemon.
 */
int run_as_daemon_func() 
{
    pid_t pid, sid;

    fflush(stdout);
    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR, "ERROR: Failed to fork");
        return FAILURE;
    }
    else if (pid > 0) {
        syslog(LOG_INFO, "Terminating Parent");
        exit(SUCCESS);
    }
    else if (pid == 0) {
        syslog(LOG_INFO, "Created Child Successfully");
        sid = setsid();
        if (sid < 0) {
            syslog(LOG_ERR, "ERROR: Failed to setsid");
            return FAILURE;
        }

        if ((chdir("/")) < 0) {
            syslog(LOG_ERR, "ERROR: Failed to chdir");
            return FAILURE;
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        int fd = open("/dev/null", O_RDWR);
        if (fd == -1) {
            syslog(LOG_PERROR, "open:%s\n", strerror(errno));
            close(fd);
            return FAILURE;       
        }

        if (dup2(fd, STDIN_FILENO)  == -1) {
            syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            close(fd);
            return FAILURE;    
        }
        if (dup2(fd, STDOUT_FILENO)  == -1) {
            syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            close(fd);
            return FAILURE;    
        }
        if (dup2(fd, STDERR_FILENO)  == -1) {
            syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            close(fd);
            return FAILURE;    
        }
        close(fd);
    }

    return SUCCESS;	
}


/*
 * Main Function:
 * 1) Parses arguments for daemon mode.
 * 2) Sets up signals.
 * 3) Creates and binds a socket.
 * 4) Optionally daemonizes.
 * 5) Accepts client connections and creates threads to handle them.
 */
int main(int argc, char *argv[])
{
    int status = SUCCESS;
    socket_thread_t *data_ptr = NULL;
    socket_thread_t *data_ptr_temp = NULL;
    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

    openlog(NULL, 0, LOG_USER);

    /* Check if daemon mode is requested */
    if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
        printf("RUNNING DAEMON\n");
        daemon_mode_enabled = 1;
        syslog(LOG_INFO, "Running aesdsocket as daemon(background)");
    }

    printf("running aesd socket\n");

    /* Register signal handlers for SIGINT and SIGTERM */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;

    if (sigaction(SIGINT, &sa, NULL) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: Failed to register SIGINT");
        return FAILURE;
    }
    if (sigaction(SIGTERM, &sa, NULL) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: Failed to register SIGTERM");
        return FAILURE;
    }
    syslog(LOG_INFO, "Signal Handler registered");


    SLIST_HEAD(socket_head, socket_thread) head;
    SLIST_INIT(&head);

    /* Create a socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == FAILURE) {
        syslog(LOG_ERR, "ERROR: Failed to create socket");
        return FAILURE;
    }
    syslog(LOG_INFO, "Socket created successfully: %d", sock_fd);

    /* Prepare hints and get address info */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *server_addr_info = NULL;
    if (getaddrinfo(NULL, SERVER_PORT, &hints, &server_addr_info) != 0) {
        syslog(LOG_ERR, "ERROR: Failed to get address");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Address returned from getaddrinfo");

    int reuse_opt = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_opt, sizeof(int)) == FAILURE) {
        syslog(LOG_ERR, "ERROR: Failed to setsockopt");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Set port reuse option");

    if (bind(sock_fd, server_addr_info->ai_addr, server_addr_info->ai_addrlen) != SUCCESS) {
        syslog(LOG_PERROR, "ERROR: Failed to bind");
        if (server_addr_info != NULL) {
            freeaddrinfo(server_addr_info);
        }
        status = FAILURE;
        goto main_exit;
    }
    syslog(LOG_INFO, "Bind Successful");

    if (server_addr_info != NULL) {
        freeaddrinfo(server_addr_info);
        syslog(LOG_INFO, "Memory Free");
    }

    if (daemon_mode_enabled) {
        syslog(LOG_INFO, "Running as daemon");
        if(run_as_daemon_func() != SUCCESS) {
            syslog(LOG_ERR, "ERROR: Failed to run as a daemon");
            status = FAILURE;
            goto main_exit;
        }
    }

    if (listen(sock_fd, 10) == -1) {
        syslog(LOG_ERR, "ERROR: Failed to listen");
        status = FAILURE;
        goto main_exit;
    }

#if (USE_AESD_CHAR_DEVICE == 0)
    /* Spawn timestamp thread if not using the character device */
    data_ptr = (socket_thread_t *)malloc(sizeof(socket_thread_t));
    if (data_ptr == NULL) {
        syslog(LOG_ERR, "ERROR: Failed to malloc");
        status = FAILURE;
        goto main_exit;
    }

    data_ptr->thread_complete = false;
    data_ptr->thread_mutex = &file_mutex;

    if (pthread_create(&data_ptr->thread_id, NULL, timestamp_thread, data_ptr) != SUCCESS) {
        syslog(LOG_ERR, "ERROR: Failed to create timer thread");
        free(data_ptr);
        data_ptr = NULL;
        status = FAILURE;
        goto main_exit;
    }
    SLIST_INSERT_HEAD(&head, data_ptr, node_count);
#endif

    /* Main server loop for handling client connections */
    while(!shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int accepted_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (accepted_fd == FAILURE) {
            syslog(LOG_ERR, "ERROR: Failed to accept");
        } else {
            syslog(LOG_INFO, "connection accepted: %d", accepted_fd);

            if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
                syslog(LOG_ERR, "ERROR: Failed to get ip");
            }
            syslog(LOG_INFO, "Accepted connection from %s", client_ip);

            data_ptr = (socket_thread_t *)malloc(sizeof(socket_thread_t));
            if (data_ptr == NULL) {
                syslog(LOG_ERR, "ERROR: Failed to malloc");
                status = FAILURE;
                goto main_exit;
            }

            data_ptr->client_socket_fd = accepted_fd;
            data_ptr->thread_complete = false;
            data_ptr->thread_mutex = &file_mutex;

            if (SUCCESS != pthread_create(&data_ptr->thread_id, NULL, data_thread, data_ptr)) {
                syslog(LOG_ERR, "ERROR: Failed to create connection thread");
                free(data_ptr);
                data_ptr = NULL;
                status = FAILURE;
                goto main_exit;
            }
            SLIST_INSERT_HEAD(&head, data_ptr, node_count);
        }

        /* Cleanup threads that have finished their work */
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
