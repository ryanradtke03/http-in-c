
// #include <string.h>


// /*
// htons() - host to network short 
// htonl() - host to network long
// ntohs() - network to host short
// ntohl() - network to host long
// */

// // Used to prep socket adress structures 
// struct addrinfo {
//     int ai_flags; // AI_PASSIVE, AI_CANONNAME, etc.
//     int ai_family; // AF_INET, AF_INET6, AF_UNSPEC (IPv4, IPv6, or either)
//     int ai_socktype; // SOCK_STREAM, SOCK_DGRAM 
//     int ai_protocol; // use 0 for "any"
//     size_t ai_addrlen; // size of ai_addr in bytes
//     struct sockaddr *ai_addr; // struct sockaddr_in or _in6
//     char *ai_canonname; // full canonical hostname

//     struct addrinfo *ai_next; // linked list, next node
// };

// // Socket address structure -------------------------------------------------------------
// struct sockaddr {
//     unsigned short sa_family; // address family, AF_xxx (AF_INET (IPv4), AF_INET6 (IPv6))
//     char sa_data[14]; // 14 bytes of protocol address, destination address
// };




// // IP address structure -------------------------------------------------------------- (in for internet)
// struct sockadd_in{
//     short int sin_family; // Address family (AF_INET)
//     unsigned short int sin_port; // Port number (16 bits) (network byte order)
//     struct in_addr sin_addr; // Internet address (IPv4)
//     unsigned char sin_zero[8]; // Padding to make structure the same size as struct sockaddr
// };

// struct in_addr {
//     unsigned long s_addr; // 32-bit IPv4 address
// };
// // ---------------------------------------------------------------------------------------


// // IPv6 address structure -----------------------------------------------------------------
// struct sockaddr_in6 {
//     short int sin6_family; // Address family (AF_INET6)
//     unsigned short int sin6_port; // Port number (16 bits)
//     unsigned long sin6_flowinfo; // IPv6 flow information
//     struct in6_addr sin6_addr; // IPv6 address
//     unsigned long sin6_scope_id; // Scope ID
// };

// struct in6_addr {
// unsigned char s6_addr[16]; // IPv6 address
// };
// ---------------------------------------------------------------------------------------

// Socket options structure ------------------------------------------------------------- (hold enough space for all options)
// struct sockaddr_storage {
//     sa_family_t ss_family; // address family
//     // all this is padding, implementation specific, ignore it:
//     char __ss_pad1[_SS_PAD1SIZE];
//     int64_t __ss_align;
//     char __ss_pad2[_SS_PAD2SIZE];
// };

// inet_ntop() (“ntop” means “network to presentation”—you can call it “network to printable")
// inet_pton() (“pton” means “presentation to network”—you can call it “printable to network”)


// Actual code here

// getaddrinfo() - get address information
// node - hostname or IP address
// service - port number or service name
// hints - pointer to addrinfo structure with desired address family, socket type, etc. (alrdy filled out)
// res - pointer to addrinfo structure to hold the results (linked lis)
// int getaddrinfo(const char *node, const char* service, const struct addrinfo* hints, struct addrinfo** res);


// domain: PF_INET (IPv4), PF_INET6 (IPv6), PF_UNIX (local socket)
// related to sockaddr_in, you can pass AF_INET or AF_INET6 instead of PF_INET or PF_INET6
// type: SOCK_STREAM (TCP), SOCK_DGRAM (UDP)
// protocol: 0 (default), IPPROTO_TCP (TCP), IPPROTO_UDP (UDP), getprotobyname() to get protocol number
//int socket(int domain, int type, int protocol);

// int s;
// struct addrinfo hints, *res;

// getaddrinfo("www.example.com", "80", &hints, &res);
// // returns a socet discriptior
// s = socket(res->ai_family, res->ai_socktype, res->ai_protocol); 

// socket descriptor, address, length
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);


// int main(int argc, char* argv[]){

    // int status;
    // struct addrinfo hints, *res, *p; // hints: for getaddrinfo, res: result list, p: pointer to current node
    // char ipstr[INET6_ADDRSTRLEN];

    // if (argc != 2) {
    //     fprintf(stderr, "usage: %s hostname\n", argv[0]);
    //     return 1;
    // }

    // // Make sure struct is empty
    // memset(&hints, 0, sizeof(hints)); // zero out the struct
    // hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
    // hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    // //hints.ai_flags = AI_PASSIVE; // fill in my IP for me (for server) (host its running on)
    // // hints.ai_flags = AI_PASSIVE;
    // // getaddrinfo(NULL, "3049" &hints, &res)

    // // Get address info
    // // Ip, port, address info, result
    // if((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0) {
    //     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    //     return 2;
    // }
    // // res now points to a linked list of 1 or more struct addrinfo

    // printf("IP addresses for %s:\n", argv[1]);

    // // Loop through all the results
    // for(p = res; p!= NULL; p = p->ai_next){
    //     void *addr;
    //     char *ipver;

    //     // get the pointer to the adress itself,
    //     // different fields in IPv4 and IPv6:
    //     if(p->ai_family == AF_INET) { // IPv4
    //         // Grab the pointer to the address itself
    //         struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
    //         addr = &(ipv4->sin_addr);
    //         ipver = "IPv4";

    //     } else { // IPv6
    //         struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
    //         addr = &(ipv6->sin6_addr);
    //         ipver = "IPv6";
    //     }

    //     // Convert the IP to a string and print it
    //     inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
    //     // IP Type, IP address
    //     printf("  %s: %s\n", ipver, ipstr);
    // }


    // int sockfd;

    // // Create a socket IPv4 or IPv6, TCP or UDP, Protocol
    // sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    // // bind the socket to the address
    // bind(sockfd, res->ai_addr, res->ai_addrlen);

    // freeaddrinfo(res); // free the linked list
    // return 0;


//     struct addrinfo hints, *res;
//     int socketfd;

//     memset(&hints, 0, sizeof(hints)); // zero out the struct
//     hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
//     hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

//     getaddrinfo("www.example.com", "3049", &hints, &res);

//     socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

//     connect(socketfd, res->ai_addr, res->ai_addrlen);
// }


// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// bacclog: max number of connections to queue
// int listen(int sockfd, int backlog);

// getaddrinfo -> socket -> bind -> listen -> accept

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
// addr is a pointer to a local struck sockadd_stroage, info about the incommection will go
    // set to sieof(struct sockadd_storage) 


    // ready to communicate on socket decriptor new fd

    // (send() recv()) - connected sockets
    // int send(int sockfd, const void *msg, int len, int flags)
        // sockfd: either your socket or the once you got with accept
        // set flags to 0;


    
    /* Example:
    char *msg = "Hello, world!";
    int len, bytes_sent;
    len = strlen(msg);
    bytes_sent = send(sockfd, msg, len, 0);   
    // returns the amount of bytes sent, compare to len to see if you must send more
    */

    // int recv(int sockfd, void *buf, int len, int flags)
    // buf is the buffer to store the incoming data
    // len is max size of the buffer
    // flags is set to 0
    // returns the number of bytes actually read into the buffer
    // returns -1 for error and 0 for connection closed

    //(sendto() recvfrom()) - unconnected sockets
    // int sendto(int sockfd, const void *msg, int len, unsigned int flags, const struct sockaddr *to, sockleh_t tolen);
    // returns the same as send()

    // int recvfrom(int sockfd, void *bud, int len, unsigned int flags, struckt sockaddr *from, int *fromlen);
    // returns the same as recv()


    // close(sockfd); // close the listening socket

    // int shutdown(int sockfd, int how)
    // how: SHUT_RD   (0) - disallow further receive operations
    //      SHUT_WR   (1) - disallow further send operations
    //      SHUT_RDWR (2) - disallow further send and receive operations
    // return 0 on success, -1 on error

    // shutdown doesnt actually close the socket, it just disallows further send/receive operations

    // #include <sys/socket.h>
    // int getpeername(int sockfd, struct sockaddr *addr, int *addrlen);
    //  addrlen should be init to sizeof(struct sockaddr)
    // returns -1 on error
    // can you inet_ntop(), getnameinfo(), or gethostbyaddr() to print / get more info

    // #include <sys/socket.h>
    // int gethostname(char *hostname, size_t size);
    // size is length in bytes of the hostname
    // returns 0 on success, -1 on error

//             Request                           Response
// Client: send() -> Server: recv() -> Server: send() -> Client :recv()



#include <stdio.h>        // for printf, fprintf
#include <stdlib.h>       // for exit
#include <string.h>       // for memset
#include <unistd.h>       // for close (if you're using sockets)
#include <errno.h>        // for errno
#include <sys/types.h>    // for socket types
#include <sys/socket.h>   // for socket functions
#include <netdb.h>        // for getaddrinfo, addrinfo, freeaddrinfo
#include <arpa/inet.h>    // for inet_ntop, inet_pton
#include <netinet/in.h>   // for sockaddr_in, sockaddr_in6
#include <sys/wait.h>    // for waitpid
#include <signal.h>       // for sigaction

#define PORT "3051" // port we're listening on
#define BACKLOG 10 // how many pending connections queue will hold


void sigchld_handler(int s){
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa){
    if(sa->sa_family == AF_INET){
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char* argv[]){

    int sockfd, new_fd; // listen on sockfd, new connection on new_fd
    struct addrinfo hints, *serverinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    // load up address structs
    memset(&hints, 0, sizeof hints); // zero out the struct
    hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE; // fill in my IP for me (for server)

    // get server address info
    if((rv = getaddrinfo(NULL, PORT, &hints, &serverinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    inet_ntop(serverinfo->ai_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    printf("server: waiting for connections on %s%s\n", s, PORT);

    // Loop through all the results and bind to the first one we can
    for(p = serverinfo; p != NULL; p = p->ai_next){

        // Create a socket
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("socket");
            continue;
        }

        // Set socket options
        // SOL_SOCKET: socket level
        // SO_REUSEADDR: allow reuse of local addresses
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
            perror("setsockopt");
            exit(1);
        }

        // Bind the socket to the address
        if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            perror("bind");
            continue;
        }
        break; // if we get here, we have successfully bound
    }

    // free the linked list
    freeaddrinfo(serverinfo);

    // Check if we successfully bound
    if(p == NULL){
        fprintf(stderr, "failed to bind\n");
        exit(1);
    }

    // Listen for incoming connections
    if(listen(sockfd, BACKLOG) == -1){
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask); // no signals blocked during handler
    sa.sa_flags = SA_RESTART; // restart functions if interrupted by handler

    // install the signal handler
    if(sigaction(SIGCHLD, &sa, NULL) == -1){
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1){ 
        // Accept a new connection
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if(new_fd == -1){
            perror("accept");
            continue;
        }

        // Get the IP address of the client
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
        printf("server: got connection from %s\n", s);

        // Fork a new process to handle the connection
        if(!fork()){
            // This is the child process
            close(sockfd); // child doesn't need the listener
     
            if(send(new_fd, "Hello, world!\n", 14, 0) == -1){
                perror("send");
            }
            close(new_fd); // Close the connection
            exit(0); // Exit the child process
        }
        close(new_fd); // parent doesn't need this
    }

    return 0;
}