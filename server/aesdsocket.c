/**********************************
 * File Name: aesdsocket.c
 * Author: Chandan Mohanta
 * Subject: Advanced Embedded Systems Design (AESD)
 * References: lecture and slides	
 * Description:
 * Continued for Assignment_6
 **********************************/

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

/* Configuration defines */
#define SERVER_PORT        "9000"
#define USE_AESD_CHAR_DEVICE   (1)
#if (USE_AESD_CHAR_DEVICE == 0)
    #define DATA_FILE_PATH     "/var/tmp/aesdsocketdata"
#elif (USE_AESD_CHAR_DEVICE == 1)
    #define DATA_FILE_PATH     "/dev/aesdchar"
#endif
#define BUFFER_LENGTH      1024
#define TIMESTAMP_INTERVAL 10  // 10 seconds interval for timestamp
#define RFC2822_FORMAT     "%a, %d %b %Y %H:%M:%S %z"

/* Global variables */
int shutdown_flag = 0;
int daemon_mode_enabled = 0;
int server_socket_fd = -1, data_file_fd = -1;
char client_ip[INET_ADDRSTRLEN];
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex for file access

/* Thread management using queue.h */
typedef struct socket_thread {
    pthread_t thread_id;
    int client_socket_fd;
    bool thread_complete;
    SLIST_ENTRY(socket_thread) entries; // For the singly linked list
} socket_thread_t;

SLIST_HEAD(socket_thread_list, socket_thread) thread_list_head;  // List of threads

/* Function declarations */
void handle_signal(int signal_number);
void terminate_program(int status_code);
void initiate_daemon_mode();
void configure_signal_handling();
void initialize_socket();
void bind_and_start_listening(struct addrinfo *server_info);
void *handle_client_connection(void *client_socket_fd);
void manage_client_data(int client_socket_fd);
void setup_daemon_mode();
void *timestamp_thread(void *arg);
void join_and_cleanup_threads();

int main(int argc, char *argv[]) 
{
    openlog(NULL, 0, LOG_USER); /* Initialize syslog */
    
    /* Initialize the SLIST head */
    SLIST_INIT(&thread_list_head);

    /* Check for -d parameter to enable daemon mode */
    if ((argc == 2) && (strcmp(argv[1], "-d") == 0))
    {
        daemon_mode_enabled = 1;
        syslog(LOG_INFO, "[INFO] Daemon mode activated.");
    }

    configure_signal_handling(); /* Register signal handlers */
    initialize_socket();         /* Setup socket and bind */

    setup_daemon_mode();         /* Handle daemon mode if specified */

#if (USE_AESD_CHAR_DEVICE == 0)
    /* Create thread for appending timestamps every 10 seconds */
    pthread_t timestamp_thread_id;
    if (pthread_create(&timestamp_thread_id, NULL, timestamp_thread, NULL) != 0) {
        syslog(LOG_ERR, "[ERROR] Failed to create timestamp thread.");
        terminate_program(EXIT_FAILURE);
    }
#endif

    /* Main server loop */
    while (!shutdown_flag)
    {
        struct sockaddr_in client_address;
        socklen_t client_address_len = sizeof(client_address);
        int client_socket = accept(server_socket_fd, (struct sockaddr*)&client_address, &client_address_len);

        if (client_socket == -1) {
            if (shutdown_flag) break;  // Exit loop if shutdown was requested
            syslog(LOG_WARNING, "[WARNING] Accepting connection failed, retrying...");
            continue;
        }

        /* Log client IP address */
        if (inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN) != NULL) {
            syslog(LOG_INFO, "Accepted connection from %s", client_ip);
        }

        /* Spawn a new thread to handle the connection */
        socket_thread_t *new_thread = (socket_thread_t *)malloc(sizeof(socket_thread_t));
        if (new_thread == NULL) {
            syslog(LOG_ERR, "[ERROR] Failed to allocate memory for new thread.");
            close(client_socket);
            continue;
        }

        new_thread->client_socket_fd = client_socket;
        new_thread->thread_complete = false;

        /* Add the new thread to the list */
        SLIST_INSERT_HEAD(&thread_list_head, new_thread, entries);

        if (pthread_create(&new_thread->thread_id, NULL, handle_client_connection, (void *)(intptr_t)client_socket) != 0) {
            syslog(LOG_ERR, "[ERROR] Failed to create thread for client connection.");
            close(client_socket);
            free(new_thread);
            continue;
        }

        /* Clean up completed threads */
        socket_thread_t *thread, *temp_thread;
        SLIST_FOREACH_SAFE(thread, &thread_list_head, entries, temp_thread) {
            if (thread->thread_complete) {
                pthread_join(thread->thread_id, NULL);
                SLIST_REMOVE(&thread_list_head, thread, socket_thread, entries);
                free(thread);
            }
        }
    }

    /* Join and clean up all threads before exiting */
    join_and_cleanup_threads();

    terminate_program(EXIT_SUCCESS); /* Clean exit */
}

/* Function to setup signal handlers for SIGINT and SIGTERM */
void configure_signal_handling()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1)
    {
        syslog(LOG_ERR, "[ERROR] Unable to register signal handlers: %s", strerror(errno));
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Signal handlers registered successfully.");
}

/* Function to setup the socket, bind, and start listening */
void initialize_socket()
{
    struct addrinfo socket_hints, *server_info = NULL;
    memset(&socket_hints, 0, sizeof(socket_hints)); /* Initialize socket_hints */
    socket_hints.ai_family = AF_INET;       /* Use IPv4 */
    socket_hints.ai_socktype = SOCK_STREAM; /* Use TCP */
    socket_hints.ai_flags = AI_PASSIVE;     /* Bind to any available IP */

    /* Create socket */
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd == -1) 
    {
        syslog(LOG_ERR, "[ERROR] Socket creation failed: %s", strerror(errno));
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Socket created: %d", server_socket_fd);

    /* Get server address information */
    if (getaddrinfo(NULL, SERVER_PORT, &socket_hints, &server_info) != 0)
    {
        syslog(LOG_ERR, "[ERROR] Address retrieval failed: %s", strerror(errno));
        freeaddrinfo(server_info);
        terminate_program(EXIT_FAILURE);
    }

    /* Set socket options for port reuse */
    int reuse_option = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_option, sizeof(int)) == -1)
    {
        syslog(LOG_ERR, "[ERROR] Failed to set socket options: %s", strerror(errno));
        freeaddrinfo(server_info);
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Port reuse options set.");

    bind_and_start_listening(server_info); /* Bind and listen on the socket */
    freeaddrinfo(server_info);             /* Free address info */
}

/* Function to bind and listen on the socket */
void bind_and_start_listening(struct addrinfo *server_info)
{
    if (bind(server_socket_fd, server_info->ai_addr, server_info->ai_addrlen) != 0)
    {
        syslog(LOG_ERR, "[ERROR] Binding socket failed: %s", strerror(errno));
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Socket bound successfully.");

    if (listen(server_socket_fd, 10) == -1)
    {
        syslog(LOG_ERR, "[ERROR] Listening on socket failed: %s", strerror(errno));
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Socket now listening for connections.");
}

/* Function to setup daemon mode */
void setup_daemon_mode()
{
    if (daemon_mode_enabled)
    {
        syslog(LOG_INFO, "[INFO] Initiating daemon mode.");
        initiate_daemon_mode();
    }
}

/* Function to handle each client connection */
void *handle_client_connection(void *client_socket_fd)
{
    int socket_fd = (intptr_t)client_socket_fd;
    manage_client_data(socket_fd);
    close(socket_fd);
    syslog(LOG_INFO, "Closed connection from %s", client_ip);

    /* Mark thread as complete */
    socket_thread_t *thread;
    SLIST_FOREACH(thread, &thread_list_head, entries) {
        if (thread->client_socket_fd == socket_fd) {
            thread->thread_complete = true;
            break;
        }
    }

    pthread_exit(NULL);
}

/* Function to process client data and respond */
void manage_client_data(int client_socket_fd)
{
    pthread_mutex_lock(&file_mutex);  // Lock the mutex before file operations

    /* Open file for appending received data */
    data_file_fd = open(DATA_FILE_PATH, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (data_file_fd == -1)
    {
        syslog(LOG_ERR, "[ERROR] File open failed: %s", strerror(errno));
        pthread_mutex_unlock(&file_mutex);  // Unlock mutex on error
        return;
    }

    char data_buffer[BUFFER_LENGTH] = {'\0'};
    bool complete_packet = false;
    int received_data = 0;

    do
    {
        memset(data_buffer, 0, BUFFER_LENGTH); /* Clear buffer */
        received_data = recv(client_socket_fd, data_buffer, BUFFER_LENGTH, 0);
        if (received_data == -1)
        {
            syslog(LOG_ERR, "[ERROR] Data reception failed: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            return;
        }

        /* Write received data to file */
        if (write(data_file_fd, data_buffer, received_data) != received_data)
        {
            syslog(LOG_ERR, "[ERROR] File write failed: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            return;
        }

        /* Check for newline indicating end of packet */
        if (memchr(data_buffer, '\n', received_data) != NULL)
        {
            complete_packet = true;
        }
    } while (!complete_packet);

    /* Reset file position to beginning */
    lseek(data_file_fd, 0, SEEK_SET);

    /* Read file content and send to client */
    int read_data = 0;
    do
    {
        memset(data_buffer, 0, BUFFER_LENGTH); /* Clear buffer */
        read_data = read(data_file_fd, data_buffer, BUFFER_LENGTH);
        if (read_data == -1)
        {
            syslog(LOG_ERR, "[ERROR] File read failed: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            return;
        }

        if (read_data > 0)
        {
            if (send(client_socket_fd, data_buffer, read_data, 0) != read_data)
            {
                syslog(LOG_ERR, "[ERROR] Sending data to client failed: %s", strerror(errno));
                pthread_mutex_unlock(&file_mutex);
                return;
            }
        }
    } while (read_data > 0);

    close(data_file_fd); /* Close the data file */
    pthread_mutex_unlock(&file_mutex);  // Unlock the mutex after file operations
}

/* Timestamp thread function */
void *timestamp_thread(void *arg)
{
#if (USE_AESD_CHAR_DEVICE == 0)
    while (!shutdown_flag)
    {
        sleep(TIMESTAMP_INTERVAL);  // Wait for 10 seconds

        time_t current_time;
        struct tm *time_info;
        char timestamp_buffer[BUFFER_LENGTH];

        time(&current_time);
        time_info = localtime(&current_time);

        strftime(timestamp_buffer, BUFFER_LENGTH, "timestamp:%a, %d %b %Y %H:%M:%S %z\n", time_info);

        pthread_mutex_lock(&file_mutex);

        data_file_fd = open(DATA_FILE_PATH, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (data_file_fd == -1)
        {
            syslog(LOG_ERR, "[ERROR] File open failed for timestamp: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            continue;
        }

        if (write(data_file_fd, timestamp_buffer, strlen(timestamp_buffer)) != strlen(timestamp_buffer))
        {
            syslog(LOG_ERR, "[ERROR] Failed to write timestamp to file: %s", strerror(errno));
        }

        close(data_file_fd);
        pthread_
