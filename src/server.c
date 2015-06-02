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



void initTargetSocket(config_t cfg);

void initCaptureFilter(config_t cfg);
//struct sockaddr_in si_other;
void forwarder(struct sockaddr_in targetSocket,const struct pcap_pkthdr* framehdr,const u_char*  buf);

/**
 * target Socket is the socket that sends the udp messages over the network for the endpoint client 
 */
void forwarder(struct sockaddr_in targetSocket,const struct pcap_pkthdr* framehdr,const u_char* buf){

}
/**
 * Start the capture session and call forward
 *
 */
void initCaptureFilter(config_t cfg){
    const char *filter = NULL;
    const char *interface = NULL;
    int buffer = 8192; 
    bpf_u_int32 maskp,netp;
    pcap_t* descr;
    struct bpf_program fp; 
    char errbuf[PCAP_ERRBUF_SIZE];
    

    /**
     * Load configuration options
     */
    config_lookup_string(&cfg, "server.libpcap.pcap-filter", &filter);
    config_lookup_string(&cfg, "server.libpcap.network-interface", &interface);
    config_setting_lookup_int(&cfg, "server.libpcap. pcap-buffer-size", &buffer);


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
        printf("Capture Started\n");
        

        // THE NULL SHOULD BE THE SOCKET...
        // Passed as user argument....
        pcap_loop(descr,-1,forwarder,NULL);

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
void initTargetSocket(config_t cfg){

}

/**
 * Main Function xD
 * Cool stuff happend from here xD
 */
int main(int argc,char * argv[]){
  config_t cfg;
  cfg = *loadConfiguration();
  initTargetSocket(cfg);
  initCaptureFilter(cfg);
  closeConfig(cfg);
  return 0;
}
