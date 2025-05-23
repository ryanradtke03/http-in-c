
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


#include <stdio.h>        // for printf, fprintf
#include <stdlib.h>       // for exit
#include <string.h>       // for memset
#include <unistd.h>       // for close (if you're using sockets)
#include <sys/types.h>    // for socket types
#include <sys/socket.h>   // for socket functions
#include <netdb.h>        // for getaddrinfo, addrinfo, freeaddrinfo
#include <arpa/inet.h>    // for inet_ntop, inet_pton
#include <netinet/in.h>   // for sockaddr_in, sockaddr_in6


int main(int argc, char* argv[]){

    int status;
    struct addrinfo hints, *res, *p; // hints: for getaddrinfo, res: result list, p: pointer to current node
    char ipstr[INET6_ADDRSTRLEN];

    if (argc != 2) {
        fprintf(stderr, "usage: %s hostname\n", argv[0]);
        return 1;
    }

    // Make sure struct is empty
    memset(&hints, 0, sizeof(hints)); // zero out the struct
    hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets


    // Get address info
    // Ip, port, address info, result
    if((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 2;
    }
    // res now points to a linked list of 1 or more struct addrinfo

    printf("IP addresses for %s:\n", argv[1]);

    // Loop through all the results
    for(p = res; p!= NULL; p = p->ai_next){
        void *addr;
        char *ipver;

        // get the pointer to the adress itself,
        // different fields in IPv4 and IPv6:
        if(p->ai_family == AF_INET) { // IPv4
            // Grab the pointer to the address itself
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";

        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // Convert the IP to a string and print it
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        // IP Type, IP address
        printf("  %s: %s\n", ipver, ipstr);
    }

    freeaddrinfo(res); // free the linked list
    return 0;
}

