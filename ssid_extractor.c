/***************************************************
* file:     pcap_sniff.c
* Date:     Fri Mai 26 13:05:00 MST 2023
* Author:   Erwan Renault
* Location: Chicoutimi CANADA
*
* RSSI capture program
* compile : gcc network_sniffer.c -I radiotap-library -lradiotap -lpcap -DNB_FRAME=10
* run : sudo ./a.out 1 2 3
*****************************************************/
#include <pcap.h>
#include <radiotap_iter.h>
#include <stdlib.h>
#include <string.h>


// SSID field information
struct ieee80211_field {
  uint8_t id;
  uint8_t length;
  char ssid[32]; // Maximum SSID length
} __attribute__((__packed__));

int x=-1,y=-1,z=-1;
FILE* mfile;

//callback called for each new transmission
void my_callback(unsigned char *user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    
}

int main(int argc, char **argv) {
    char* dev_name;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    pcap_if_t* alldevs;
    
    if (argc>=3) {
        x = atoi(*(argv + 1));
        y = atoi(*(argv + 2));
        if (argc>=4)
            z = atoi(*(argv + 3));
    }
    for(argc; --argc;) {
        printf("%i,%s\n",argc, *(argv+argc));
    }
    if(pcap_findalldevs(&alldevs, errbuf)) {
        printf("%s\n",errbuf);
        exit(1);
    }
    printf("Devices: \n");
    for(;alldevs->next!=0; alldevs=alldevs->next)
        printf("\t %s\n",alldevs->name);

    dev_name = "wlp2s0";
    printf("Start Service : %s\n", dev_name);

    //pcap_compile();

    descr = pcap_open_live(dev_name,BUFSIZ,0,-1,errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    mfile = fopen("out.csv", "a");
    pcap_loop(descr,-1,my_callback,NULL);
    printf("Service Stop\n");
    fclose(mfile);

    return 0;
}
