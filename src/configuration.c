#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>

config_t* loadConfiguration(void){
    config_t* cfg = (config_t*)malloc(sizeof(config_t));;
    config_init(cfg);
    if(! config_read_file(cfg, "/etc/syslog-forward.cfg")){
       fprintf(stderr, "Error loading configuration file /etc/syslog-forward.cfg %d - %s\n",
                       config_error_line(cfg), config_error_text(cfg));
    }

   return cfg;
}

void closeConfig(config_t cf){
  config_destroy(&cf);
}
