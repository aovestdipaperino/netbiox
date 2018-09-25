/*
 * May you do good and not evil
   May you find forgiveness for yourself and forgive others
   May you share freely, never taking more than you give.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <error.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/param.h>
#include <ctype.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <syslog.h>

#define MAX_NAME_LENGTH 17

typedef struct namerecord {
    char* name;
    uint32_t ip_address;
    struct namerecord* next;
} namerecord;

typedef char byte;

namerecord* list_head = NULL;
// Delimiters used in the lmhosts file.
const char* DELIM = " \t";
const int NAME_OFFSET = 13;
const char* PID_FILE_NAME = "//var//run//samba//nbiox.pid";

/**
 * Adds an element to the name record list, in front of all others.
 * Positive side effect: duplicate names will be handled by last to first,
 * giving priority to the last because it will be in front of all others.
 * @param name
 * @param ip_address
 */
void addElement(char* name, uint32_t ip_address) {
    namerecord* new_head = malloc(sizeof(namerecord));
    new_head -> name = name;
    new_head -> ip_address = ip_address;
    new_head -> next = list_head;
    list_head = new_head;
}

/**
 * Given a name, it returns the associated IP address.
 * @param name
 * @return
 */
uint32_t findElementByName(char *name) {
    namerecord* cur = list_head;
    while(cur) {
        if (!strncmp(cur -> name, name, MAX_NAME_LENGTH)) {
            return cur->ip_address;
        }
        cur = cur -> next;
    }
    return 0;
}

/**
 * Scans the name record list and returns TRUE if the ip_address is present
 * @param ip_address
 * @return
 */
char ipAddressExists(uint32_t ip_address) {
    namerecord* cur = list_head;
    while(cur) {
        if (cur->ip_address == ip_address) {
            return 1;
        }
        cur = cur -> next;
    }
    return 0;
}

/**
 * Prints the name record list for debugging purposes.
 */
void printList() {
    namerecord* cur = list_head;
    while(cur) {
        if (cur ->ip_address && cur->name) {
            printf("%s %s\n",
                   inet_ntoa(*(struct in_addr *) &(cur->ip_address)),
                   cur->name);
        }
        cur = cur -> next;
    }
}

/**
 * convert a string into uppdercase.
 * @param sPtr
 * @return
 */
char* uppercase( char *sPtr )
{
    char* result = sPtr;
    while( *sPtr != '\0' )
    {
        *sPtr = toupper( ( unsigned char ) *sPtr );
        sPtr++;
    }
    return result;
}

int isWhiteSpace(char c) {
    return (c== '\r' || c== '\n'|| c == ' '|| c== '\t');
}

/**
 * Removes trailing '\r' and '\n' and spaces.
 * @param name
 * @return
 */
char* trim(char* name) {
    for(int i=strlen(name) - 1; i >=0; i--) {
        if (isWhiteSpace(name[i]))
            name[i] = '\0';
        else
            break;
    }
    if(strlen(name) > 0) {
        while(isWhiteSpace(*name)) name++;
    }
    return name;
}

/**
 * Removes the comment part by truncating
 * @param name
 */
void removeComment(char* name){
    for(int i=0; i < strlen(name); i++) {
        if (name[i] == '#') {
            name[i] = '\0';
            return;
        }
    }
}

int parseLmhostsLine(char * line, char **name, char **ip_address) {
    removeComment(line);
    line = trim(line);

    if (strlen(line) < 1) return -1;
    char* tok1 = strtok(line, DELIM);
    if (!tok1) return -1;

    char* tok2 = strtok(NULL, DELIM);
    if (!tok2) return -1;

    if (strtok(NULL, DELIM)) return -1;

    *name = malloc(MAX(strlen(tok2), MAX_NAME_LENGTH));
    strncpy(*name, uppercase(tok2), MAX_NAME_LENGTH);

    *ip_address = malloc(MAX(strlen(tok1), MAX_NAME_LENGTH));
    strncpy(*ip_address, tok1, MAX_NAME_LENGTH);

    return 0;
}

void readLmhostsFile() {
    FILE* file = fopen("//etc//samba//lmhosts", "r");
    if (file == NULL) return;

    char * line = NULL;
    size_t len = 0;
    char *name, *ip_address;


    while ((getline(&line, &len, file)) != -1) {
        if (parseLmhostsLine(line, &name, &ip_address) == 0) {
            struct in_addr temp;
            inet_aton(ip_address, & temp);
            addElement(name, temp.s_addr);
            syslog(LOG_INFO, "NETBIOX mapping %s -> %s", name, ip_address);
        }
    }

    fclose(file);
    if (line)
        free(line);
}

u_int32_t getFreeDeviceIp() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        // TODO: check for broadcast flag
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            if (!ipAddressExists(sa->sin_addr.s_addr)) {
                freeifaddrs(ifap);
                return sa->sin_addr.s_addr;
            }
        }
    }

    freeifaddrs(ifap);
    return 0;
}

char* ipToString(uint32_t ipaddress) {
    return inet_ntoa(*(struct in_addr *) &(ipaddress));
}

char response[62];
char name[MAX_NAME_LENGTH];

char* convertToName(char* packet) {
    memset(name, '\0', MAX_NAME_LENGTH);
    for(int i = 0; i < 16; i++) {
        name[i] = ((packet[i*2 + NAME_OFFSET] - 'A') << 4) +  (packet[i*2 + NAME_OFFSET + 1] - 'A');
    }
    return name;
}


void createResponse(char* packet, uint32_t ip_address) {
    response[0] = packet[0];  response[1] = packet[1];
    response[2] = (byte)0x85; response[3] = (byte) 0x80;
    response[4] = (byte)0x00; response[5] = (byte) 0x00;
    response[6] = (byte)0x00; response[7] = (byte) 0x01;
    response[8] = (byte)0x00; response[9] = (byte) 0x00;
    response[10] = (byte)0x00; response[11] = (byte) 0x00;

    for(int i= 0; i < 34; i++) {
        response[12+i] = packet[NAME_OFFSET -1 + i];
    }
    response[46] = (byte)0x00; response[47] = (byte) 0x20;
    response[48] = (byte)0x00; response[49] = (byte) 0x01;
    response[50] = (byte)0x00; response[51] = (byte) 0x03;
    response[52] = (byte)0xf4; response[53] = (byte) 0x80;
    response[54] = (byte)0x00; response[55] = (byte) 0x06;
    response[56] = (byte)0x00; response[57] = (byte) 0x00;

    response[61] = ip_address >> 24;
    response[60] = (ip_address & 0x00FF0000) >> 16;
    response[59] = (ip_address & 0x0000FF00) >> 8;
    response[58] = (byte) ip_address & 0xFF;
}

int isNameQueryPacket(char* packet) {
    return packet[2] == 0x01 && packet[3] == 0x10
           && packet[4] == 0x00 && packet[5] == 0x01  // Questions == 1
           && packet[6] == 0x00 && packet[7] == 0x00  // Answers == 0
           && packet[8] == 0x00 && packet[9] == 0x00  // Authority RR == 0
           && packet[10] == 0x00 && packet[11] == 0x00 ; // Additional RR == 0
}

int is_daemon = 0;

void set_is_daemon(char* arg) {
    is_daemon = (strlen(arg) == 2) && (arg[0] =='-') && (arg[1] == 'D');
}

void signal_handler(int sig) {
    syslog(LOG_INFO, "NETBIOX terminating on signal\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    if (argc == 2) {
        set_is_daemon(argv[1]);
    }

    if (is_daemon) {
        pid_t  pid, sid;
        pid = fork();

        if (pid < 0) exit(EXIT_FAILURE);
        if (pid > 0) {
            exit(EXIT_SUCCESS);
        }

        FILE* pid_h = fopen(PID_FILE_NAME, "w");
        char pidc[10];
        sprintf(pidc, "%d\n", getpid());
        fwrite(pidc, 1, 10, pid_h);
        fclose(pid_h);

        umask(0);

        sid = setsid();
        if (sid < 0) exit(EXIT_FAILURE);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGKILL, signal_handler);

    syslog(LOG_INFO, "NETBIOX: started\n");
    readLmhostsFile();

    int listenfd = 0, connfd = 0, err;
    struct sockaddr_in serv_addr;
    struct sockaddr_in clientaddr; /* client addr */
    u_int32_t device_to_use = getFreeDeviceIp();

    if (device_to_use == 0) {
        syslog(LOG_ERR, "NETBIOX: cannot find an interface available. Quitting.\n");
        exit(EXIT_FAILURE);
    } else {
        syslog(LOG_INFO, "NETBIOX: listening to %s\n", ipToString(device_to_use));
    }

    char sendBuff[1025];
    time_t ticks;
    int broadcast = 1;
    socklen_t clientlen; /* byte size of client's address */

    err = listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(listenfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    if (err < 0) {
        syslog(LOG_ERR, "NETBIOSX: Error creating the socket\n");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(137);


    err = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (err < 0) {
        syslog(LOG_ERR, "NETBIOX: Error binding the socket\n");
        return -1;
    }

     int bytes;
    clientlen = sizeof(clientaddr);
    while(1)
    {
        recvfrom(listenfd, sendBuff, 1024, 0,
                     (struct sockaddr *) &clientaddr, &clientlen);


        if (isNameQueryPacket(sendBuff)) {
            char* name = trim(convertToName(sendBuff));
            uint32_t ip_address = findElementByName(name);
            if (ip_address) {
                createResponse(sendBuff, ip_address);
                err = sendto(listenfd, response, 62, 0,
                           (struct sockaddr *) &clientaddr, clientlen);
            }
        }
        close(connfd);
    }
}
