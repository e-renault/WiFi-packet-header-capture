/***************************************************
* file:     pcap_sniff.c
* Date:     Fri Mai 26 13:05:00 MST 2023
* Author:   Erwan Renault
* Location: Chicoutimi CANADA
*
* RSSI capture program
* compile : gcc rssi_extractor.c -I radiotap-library -lradiotap -lpcap -DNB_FRAME=10
* run : sudo ./a.out 1 2 3
*****************************************************/
#include <pcap.h>
#include <radiotap_iter.h>
#include <stdlib.h>
#include <string.h>

#define IEEE80211_FROM_DS 0b10<<6
#define IEEE80211_TO_DS 0b01<<6

//nb of frames per set (-1 is infinity)
#ifndef NB_FRAME
    #define NB_FRAME -1
#endif

//header frame for ieee80211 protocol 
struct ieee80211_header {
  unsigned short frame_control;
  unsigned short frame_duration;
  unsigned char adr1[6];
  unsigned char adr2[6];
  unsigned char adr3[6];
  unsigned short sequence_control;
  unsigned char adr4[6];
};

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

    /******* Filtering *******/
    // get radiotap header
    struct ieee80211_radiotap_header* rtap_hdr = ( struct ieee80211_radiotap_header *) packet;
    if(rtap_hdr->it_version != 0) return;// check version it is not a 0 it's not radiotap
    
    // start iterator
    struct ieee80211_radiotap_iterator iter;
    int err = ieee80211_radiotap_iterator_init(&iter, rtap_hdr, pkthdr->caplen, NULL);
    if (err) return;

    //get ieee80211 header
    struct ieee80211_header* wifi_h = (struct ieee80211_header *) ( packet + iter._max_length);

    // Filter only FromDS=0, ToDS=1
    uint8_t FROM_DS = (wifi_h->frame_control & (IEEE80211_FROM_DS)) == IEEE80211_FROM_DS;
    uint8_t TO_DS = (wifi_h->frame_control & (IEEE80211_TO_DS)) == IEEE80211_TO_DS;
    if(! (FROM_DS == 0 && TO_DS == 1)) return;

    // Get the length of the IEEE 802.11 header
    int wifi_len = pkthdr->caplen - (iter._max_length + sizeof(struct ieee80211_header));

    // Check if the packet has enough data for the IEEE 802.11 header
    if (wifi_len < sizeof(struct ieee80211_header)) return;


    /******* Extracting *******/
    // get source informations
    char ssid[32] = "\0";
    char SA[18];
    char DA[18];
    char BSSID[18];
    int dbm_antsignal_sum = 0; //RSSI
    int measure_count = 0;
    uint8_t antenna_index = 0;
    uint64_t channel = -1;
    uint64_t tsft = -1;
    uint64_t flags = -1;
    uint64_t data_rate = -1;
    uint64_t rx_flag = -1;
    uint64_t timestamp = -1;
    uint64_t mcs = 0;
    uint64_t ampdu_status = 0;

    // Extract the SSID from the IEEE 802.11 header
    struct ieee80211_field* ssid_header = (struct ieee80211_field *) (wifi_h->adr4 + 6 -6);
    if (ssid_header->id == 0 && ssid_header->length <= 32 && ssid_header->length>0) {
        memcpy(ssid, ssid_header->ssid, ssid_header->length);
        ssid[ssid_header->length] = '\0';
    }

    // get readable mac address
    if (FROM_DS == 0 && TO_DS == 0) {
        sprintf(DA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr1[0], wifi_h->adr1[1], wifi_h->adr1[2], wifi_h->adr1[3], wifi_h->adr1[4], wifi_h->adr1[5]);
        sprintf(SA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr2[0], wifi_h->adr2[1], wifi_h->adr2[2], wifi_h->adr2[3], wifi_h->adr2[4], wifi_h->adr2[5]);
        sprintf(BSSID,  "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr3[0], wifi_h->adr3[1], wifi_h->adr3[2], wifi_h->adr3[3], wifi_h->adr3[4], wifi_h->adr3[5]);
    } else if (FROM_DS == 0 && TO_DS == 1) {
        sprintf(BSSID,  "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr1[0], wifi_h->adr1[1], wifi_h->adr1[2], wifi_h->adr1[3], wifi_h->adr1[4], wifi_h->adr1[5]);
        sprintf(SA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr2[0], wifi_h->adr2[1], wifi_h->adr2[2], wifi_h->adr2[3], wifi_h->adr2[4], wifi_h->adr2[5]);
        sprintf(DA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr3[0], wifi_h->adr3[1], wifi_h->adr3[2], wifi_h->adr3[3], wifi_h->adr3[4], wifi_h->adr3[5]);
    } else if (FROM_DS == 1 && TO_DS == 0) {
        sprintf(DA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr1[0], wifi_h->adr1[1], wifi_h->adr1[2], wifi_h->adr1[3], wifi_h->adr1[4], wifi_h->adr1[5]);
        sprintf(BSSID,  "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr2[0], wifi_h->adr2[1], wifi_h->adr2[2], wifi_h->adr2[3], wifi_h->adr2[4], wifi_h->adr2[5]);
        sprintf(SA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr3[0], wifi_h->adr3[1], wifi_h->adr3[2], wifi_h->adr3[3], wifi_h->adr3[4], wifi_h->adr3[5]);
    } else if (FROM_DS == 1 && TO_DS == 1) {
        //sprintf(Receiver, "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr1[0], wifi_h->adr1[1], wifi_h->adr1[2], wifi_h->adr1[3], wifi_h->adr1[4], wifi_h->adr1[5]);
        //sprintf(Transmitter, "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr2[0], wifi_h->adr2[1], wifi_h->adr2[2], wifi_h->adr2[3], wifi_h->adr2[4], wifi_h->adr2[5]);
        sprintf(DA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr3[0], wifi_h->adr3[1], wifi_h->adr3[2], wifi_h->adr3[3], wifi_h->adr3[4], wifi_h->adr3[5]);
        sprintf(SA,     "%02X:%02X:%02X:%02X:%02X:%02X", wifi_h->adr4[0], wifi_h->adr4[1], wifi_h->adr4[2], wifi_h->adr4[3], wifi_h->adr4[4], wifi_h->adr4[5]);
    }

    // get packets //https://man.freebsd.org/cgi/man.cgi?query=radiotap&apropos=0&sektion=9&manpath=FreeBSD+11-current&format=html
    while(ieee80211_radiotap_iterator_next(&iter)==0){
        switch (iter.this_arg_index) {
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                dbm_antsignal_sum += (int)*(iter.this_arg)-256;
                measure_count++;
                break;
            case IEEE80211_RADIOTAP_ANTENNA:antenna_index |= 1<<(uint8_t) *(iter.this_arg);break;
            case IEEE80211_RADIOTAP_TSFT:tsft = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_FLAGS:flags = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_RATE:data_rate = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_CHANNEL:channel = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_RX_FLAGS:rx_flag = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_TIMESTAMP:timestamp = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_MCS:mcs = (uint64_t)* (iter.this_arg);break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:ampdu_status = (uint64_t)* (iter.this_arg);break;
            default:printf("Uncatched frame [%i]\n ", iter.this_arg_index);
        }
    }
    if (measure_count == 0) return;//empty/invalid iterator
    

    /******* Logging *******/
    char str[1000];
    //sprintf(str, "%i,%i,%i,%s,%s,%s,%s,%i,%i,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", x, y, z, ssid, BSSID, SA,DA,dbm_antsignal_sum/measure_count, measure_count, antenna_index, channel, tsft, flags, data_rate, rx_flag, timestamp, mcs, ampdu_status);
    sprintf(str, "%s,%i%i,%s,%s,%s,%f,%i\n", ssid, FROM_DS, TO_DS, SA, DA, BSSID, (float)dbm_antsignal_sum/measure_count, measure_count);
    printf("%s", str);
    fprintf(mfile, "%s", str);
    fflush(mfile);
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

    descr = pcap_open_live(dev_name,BUFSIZ,0,-1,errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    mfile = fopen("out.csv", "a");
    pcap_loop(descr,NB_FRAME,my_callback,NULL);
    printf("Service Stop\n");
    fclose(mfile);

    return 0;
}
