/**************************************************************************************************
 * File Name: aesdsocket.c
 * Author: Chandan Mohanta
 * Subject: Advanced Embedded Systems Design (AESD)
 * References: lecture and slides
 * Description:
 * A network socket server that listens on port 9000, accepts client connections, logs received data to a file, and sends it back.
 * Supports daemon mode and handles SIGINT/SIGTERM for shutdown.
 **************************************************************************************************/

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

/* Configuration defines */
#define SERVER_PORT        "9000"
#define DATA_FILE_PATH     "/var/tmp/aesd_socket_data"
#define BUFFER_LENGTH      1024

/* Global variables */
int shutdown_flag = 0;
int daemon_mode_enabled = 0;
int server_socket_fd = -1, client_socket_fd = -1, data_file_fd = -1;

/* Function declarations */
void handle_signal(int signal_number);
void terminate_program(int status_code);
void initiate_daemon_mode();
void configure_signal_handling();
void initialize_socket();
void process_connection();
void bind_and_start_listening(struct addrinfo *server_info);
void accept_client_and_handle_data();
void manage_client_data();
void setup_daemon_mode();

int main(int argc, char *argv[]) 
{
    openlog(NULL, 0, LOG_USER); /* Initialize syslog */

    /* Check for -d parameter to enable daemon mode */
    if ((argc == 2) && (strcmp(argv[1], "-d") == 0))
    {
        daemon_mode_enabled = 1;
        syslog(LOG_INFO, "[INFO] Daemon mode activated.");
    }

    configure_signal_handling(); /* Register signal handlers */
    initialize_socket();         /* Setup socket and bind */

    setup_daemon_mode();         /* Handle daemon mode if specified */

    /* Main server loop */
    while (!shutdown_flag)
    {
        accept_client_and_handle_data(); /* Handle each client connection */
    }

    terminate_program(EXIT_SUCCESS); /* Clean exit */
}

/* Function to setup signal handlers for SIGINT and SIGTERM */
void configure_signal_handling()
{
    if (signal(SIGINT, handle_signal) == SIG_ERR || signal(SIGTERM, handle_signal) == SIG_ERR)
    {
        syslog(LOG_ERR, "[ERROR] Unable to register signal handlers.");
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
        syslog(LOG_ERR, "[ERROR] Socket creation failed.");
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Socket created: %d", server_socket_fd);

    /* Get server address information */
    if (getaddrinfo(NULL, SERVER_PORT, &socket_hints, &server_info) != 0)
    {
        syslog(LOG_ERR, "[ERROR] Address retrieval failed.");
        freeaddrinfo(server_info);
        terminate_program(EXIT_FAILURE);
    }

    /* Set socket options for port reuse */
    int reuse_option = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_option, sizeof(int)) == -1)
    {
        syslog(LOG_ERR, "[ERROR] Failed to set socket options.");
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
        syslog(LOG_ERR, "[ERROR] Binding socket failed.");
        terminate_program(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "[INFO] Socket bound successfully.");

    if (listen(server_socket_fd, 10) == -1)
    {
        syslog(LOG_ERR, "[ERROR] Listening on socket failed.");
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

/* Function to accept client connections and handle data */
void accept_client_and_handle_data()
{
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&client_address, &client_address_len);
    if (client_socket_fd == -1)
    {
        syslog(LOG_WARNING, "[WARNING] Accepting connection failed, retrying...");
        return; /* Retry accepting connections */
    }
    syslog(LOG_INFO, "[INFO] Connection accepted: %d", client_socket_fd);

    manage_client_data(); /* Handle incoming client data */
}

/* Function to process client data and respond */
void manage_client_data()
{
    /* Open file for appending received data */
    data_file_fd = open(DATA_FILE_PATH, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (data_file_fd == -1)
    {
        syslog(LOG_ERR, "[ERROR] File open failed.");
        terminate_program(EXIT_FAILURE);
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
            syslog(LOG_ERR, "[ERROR] Data reception failed.");
            terminate_program(EXIT_FAILURE);
        }

        /* Write received data to file */
        if (write(data_file_fd, data_buffer, received_data) != received_data)
        {
            syslog(LOG_ERR, "[ERROR] File write failed.");
            terminate_program(EXIT_FAILURE);
        }

        /* Check for newline indicating end of packet */
        if (strchr(data_buffer, '\n') != NULL)
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
            syslog(LOG_ERR, "[ERROR] File read failed.");
            terminate_program(EXIT_FAILURE);
        }

        if (read_data > 0)
        {
            if (send(client_socket_fd, data_buffer, read_data, 0) != read_data)
            {
                syslog(LOG_ERR, "[ERROR] Sending data to client failed.");
                terminate_program(EXIT_FAILURE);
            }
        }
    } while (read_data > 0);

    close(data_file_fd); /* Close the data file */
    close(client_socket_fd); /* Close the client socket */
    syslog(LOG_INFO, "[INFO] Connection closed.");
}

/* Signal handler for SIGINT and SIGTERM */
void handle_signal(int signal_number)
{
    if ((signal_number == SIGINT) || (signal_number == SIGTERM))
    {
        shutdown_flag = 1;
        syslog(LOG_DEBUG, "[DEBUG] Signal caught, shutting down.");
        terminate_program(EXIT_SUCCESS);
    }
}

/* Function to close all file descriptors and exit */
void terminate_program(int status_code)
{
    /* Close server socket if open */
    if (server_socket_fd >= 0) 
    {
        syslog(LOG_INFO, "[INFO] Closing server socket: %d", server_socket_fd);
        close(server_socket_fd);
        syslog(LOG_INFO, "[INFO] Server socket closed.");
    }

    /* Close client socket if open */
    if (client_socket_fd >= 0) 
    {
        syslog(LOG_INFO, "[INFO] Closing client socket: %d", client_socket_fd);
        close(client_socket_fd);
        syslog(LOG_INFO, "[INFO] Client socket closed.");
    }

    /* Close data file descriptor if open */
    if (data_file_fd >= 0) 
    {
        syslog(LOG_INFO, "[INFO] Closing data file descriptor: %d", data_file_fd);
        close(data_file_fd);
        syslog(LOG_INFO, "[INFO] Data file descriptor closed.");
    }

    /* Remove data file */
    if (remove(DATA_FILE_PATH) == 0) 
    {
        syslog(LOG_INFO, "[INFO] Data file removed.");
    }
    else
    {
        syslog(LOG_ERR, "[ERROR] Failed to remove data file.");
    }

    closelog(); /* Close syslog */
    exit(status_code); /* Exit the program with the provided status code */
}

/* Function to daemonize the process */
void initiate_daemon_mode()
{
    pid_t process_id = fork();
    if (process_id < 0)
    {
        syslog(LOG_ERR, "[ERROR] Forking process failed.");
        terminate_program(EXIT_FAILURE);
    }
    else if (process_id > 0) exit(EXIT_SUCCESS); /* Terminate parent process */

    setsid(); /* Create a new session */
    chdir("/"); /* Change working directory */

    /* Redirect standard file descriptors to /dev/null */
    int null_fd = open("/dev/null", O_RDWR);
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    close(null_fd);
}
