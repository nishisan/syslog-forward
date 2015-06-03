#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <libconfig.h>
#include "common/default.h"
#include "common/configuration.h"

//CONFIGURATION



socketSender* initTargetSocket(config_t cfg);

void initCaptureFilter(config_t cfg);
//struct sockaddr_in si_other;
void forwarder(u_char *args,const struct pcap_pkthdr* framehdr,const u_char*  buf);

/**
 * target Socket is the socket that sends the udp messages over the network for the endpoint client 
 */
void forwarder(u_char *args,const struct pcap_pkthdr* framehdr,const u_char* buf){
   socketSender *sender = (socketSender *) args;
   int len,max_offset = framehdr->caplen;
   iphdr ip;
   tcphdr tcp;
    
   /* IP */
   ip.offset = 14;
   if (IP_VERSION(buf,ip.offset) != 4)
       return;
   ip.proto = IP_PROTOCOL(buf,ip.offset);
   ip.src = IP_SRC(buf,ip.offset);
   ip.dst = IP_DST(buf,ip.offset);
   ip.data_offset = ip.offset + IP_SIZEOF_HDR(buf,ip.offset);
   if (max_offset > IP_TOTALLENGTH(buf,ip.offset) + ip.offset)
       ip.max_offset = IP_TOTALLENGTH(buf,ip.offset) + ip.offset;
   else
       ip.max_offset = max_offset;
   /* UDP */
   if (ip.proto != 17 ){
       //return;
   }
   tcp.offset = ip.data_offset;
   tcp.dst = TCP_DST(buf,tcp.offset);
   tcp.src = TCP_SRC(buf,tcp.offset);
   tcp.data_offset = tcp.offset + 8;
   sendto(sender->socket_type, buf,  ip.max_offset, 0, (struct sockaddr *)&sender->socket, sizeof(sender->socket));
   printf("Sent packet with size: %d\n", ip.max_offset);
}
/**
 * Start the capture session and call forward
 *
 */
void initCaptureFilter(config_t cfg){
    const char *filter = NULL;
    const char *interface = NULL;
    long int buffer = 8192; 
    bpf_u_int32 maskp,netp;
    pcap_t* descr;
    struct bpf_program fp; 
    char errbuf[PCAP_ERRBUF_SIZE];
    socketSender sender = *initTargetSocket(cfg);
    printf("SocketType is %d\n", sender.socket_type);
    /**
     * Load configuration options
     */
    config_lookup_string(&cfg, "server.libpcap.pcap-filter", &filter);
    config_lookup_string(&cfg, "server.libpcap.network-interface", &interface);
    config_lookup_int(&cfg, "server.libpcap.pcap-buffer-size", &buffer);



    if(filter){
      if(interface){
        pcap_lookupnet(interface,&netp,&maskp,errbuf);
        descr = pcap_open_live(interface,BUFSIZ,1,-1,errbuf);
        if(descr == NULL){ 
          printf("pcap_open_live(): %s\n",errbuf); 
          exit(1); 
        }

        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,filter,0,netp) == -1){
          fprintf(stderr,"Error calling pcap_compile\n"); 
          exit(1);
        }
      
        if(pcap_setfilter(descr,&fp) == -1){
          fprintf(stderr,"Error setting filter\n");
          exit(1);  
        }
        printf("Capture Started Buffer is %d\n",buffer);
        

        // THE NULL SHOULD BE THE SOCKET...
        // Passed as user argument....

        pcap_loop(descr,-1,forwarder,(u_char *)&sender);

      }else{
        //no interface in config
      } 
    }else{
      // no filter in config...
    }
}

/**
 * Init the sender socket...
 * This socket is the one used to send stuff over network..
 * as UDP packets xD
 */
socketSender* initTargetSocket(config_t cfg){
  long int port;
  struct sockaddr_in targetSocket;
  socketSender* sender = ( socketSender*)malloc(sizeof(socketSender));
  const char *srv_ip = NULL;
  int socketType  ;
 
  config_lookup_int(&cfg, "server.target.destination-port", &port);
  config_lookup_string(&cfg, "server.target.destination-address", &srv_ip);
  printf("Destination is %s\n",srv_ip); 
  targetSocket.sin_family = AF_INET;
  targetSocket.sin_port = htons(port);
  if (inet_aton(srv_ip, &targetSocket.sin_addr)==0) {
       fprintf(stderr, "inet_aton() failed\n");
       exit(1);
    }

  if ((socketType=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
           exit(1);

  sender->socket_type = socketType;
  sender->socket = targetSocket;
  return sender;
}

/**
 * Main Function xD
 * Cool stuff happend from here xD
 */
int main(int argc,char * argv[]){
  config_t cfg;
  cfg = *loadConfiguration();
  initCaptureFilter(cfg);
  closeConfig(cfg);
  return 0;
}
