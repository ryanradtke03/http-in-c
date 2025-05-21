
#include <string.h>

/*
htons() - host to network short 
htonl() - host to network long
ntohs() - network to host short
ntohl() - network to host long
*/

// Used to prep socket adress structures 
struct addrinfo {
    int ai_flags; // AI_PASSIVE, AI_CANONNAME, etc.
    int ai_family; // AF_INET, AF_INET6, AF_UNSPEC (IPv4, IPv6, or either)
    int ai_socktype; // SOCK_STREAM, SOCK_DGRAM 
    int ai_protocol; // use 0 for "any"
    size_t ai_addrlen; // size of ai_addr in bytes
    struct sockaddr *ai_addr; // struct sockaddr_in or _in6
    char *ai_canonname; // full canonical hostname

    struct addrinfo *ai_next; // linked list, next node
};

// Socket address structure -------------------------------------------------------------
struct sockaddr {
    unsigned short sa_family; // address family, AF_xxx (AF_INET (IPv4), AF_INET6 (IPv6))
    char sa_data[14]; // 14 bytes of protocol address, destination address
};




// IP address structure -------------------------------------------------------------- (in for internet)
struct sockadd_in{
    short int sin_family; // Address family (AF_INET)
    unsigned short int sin_port; // Port number (16 bits) (network byte order)
    struct in_addr sin_addr; // Internet address (IPv4)
    unsigned char sin_zero[8]; // Padding to make structure the same size as struct sockaddr
};

struct in_addr {
    unsigned long s_addr; // 32-bit IPv4 address
};
// ---------------------------------------------------------------------------------------


// IPv6 address structure -----------------------------------------------------------------
struct sockaddr_in6 {
    short int sin6_family; // Address family (AF_INET6)
    unsigned short int sin6_port; // Port number (16 bits)
    unsigned long sin6_flowinfo; // IPv6 flow information
    struct in6_addr sin6_addr; // IPv6 address
    unsigned long sin6_scope_id; // Scope ID
};

struct in6_addr {
unsigned char s6_addr[16]; // IPv6 address
};
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>