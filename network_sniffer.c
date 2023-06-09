/***************************************************
* file:     pcap_sniff.c
* Date:     Fri Mai 26 13:05:00 MST 2023
* Author:   Erwan Renault
* Location: Chicoutimi CANADA
*
* RSSI capture program
* compile : gcc network_sniffer.c -I radiotap-library -lradiotap -lpcap
* run : sudo ./a.out "xyz: 0 0 0"| tee data/000.csv
*****************************************************/
#include <pcap.h>
#include <radiotap_iter.h>
#include <stdlib.h>
#include <string.h>

#define IEEE80211_FROM_DS 0b10<<6
#define IEEE80211_TO_DS 0b01<<6

//nb of frames per set (-1 is infinity)
#ifndef NB_FRAME
    #define NB_FRAME 1
#endif

//header frame for ieee80211 protocol 
struct ieee80211_header {
  unsigned short frame_control;
  unsigned short frame_duration;
  unsigned char address1[6];
  unsigned char address2[6];
  unsigned char address3[6];
  unsigned short sequence_control;
  unsigned char address4[6];
};

// SSID field information
struct ieee80211_field {
  uint8_t id;
  uint8_t length;
  char ssid[32]; // Maximum SSID length
} __attribute__((__packed__));

//callback called for each new transmission
void my_callback(char *user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {

    // get radiotap header
    struct ieee80211_radiotap_header* rtap_hdr = ( struct ieee80211_radiotap_header *) packet;
    if(rtap_hdr->it_version != 0) return;// check version it is not a 0 it's not radiotap
    
    // start iterator
    struct ieee80211_radiotap_iterator iter;
    int err = ieee80211_radiotap_iterator_init(&iter, rtap_hdr, pkthdr->caplen, NULL);
    if (err) return;

    //get ieee80211 header
    struct ieee80211_header* wifi_hdr = (struct ieee80211_header *) ( packet + iter._max_length);

    if(! ((wifi_hdr->frame_control & (IEEE80211_FROM_DS | IEEE80211_TO_DS)) == (IEEE80211_TO_DS))) return;// Filter only FromDS=0, ToDS=1

    // Get the length of the IEEE 802.11 header
    int wifi_len = pkthdr->caplen - (iter._max_length + sizeof(struct ieee80211_header));

    // Check if the packet has enough data for the IEEE 802.11 header
    //if (wifi_len < sizeof(struct ieee80211_header)) return;


    // get source informations
    char ssid[32] = "Empty";
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
    struct ieee80211_field* ssid_header = (struct ieee80211_field *) (wifi_hdr->address4 + 6 -6);
    if (ssid_header->id == 0 && ssid_header->length <= 32 && ssid_header->length>0) {
        memcpy(ssid, ssid_header->ssid, ssid_header->length);
        ssid[ssid_header->length] = '\0';
    }
    printf("%s,", ssid);


    // get readable mac address
    sprintf(BSSID, "%02X:%02X:%02X:%02X:%02X:%02X", wifi_hdr->address2[0], wifi_hdr->address2[1], wifi_hdr->address2[2], wifi_hdr->address2[3], wifi_hdr->address2[4], wifi_hdr->address2[5]);

    /**
    while (ieee80211_radiotap_iterator_next(&iter)==0) {
        switch (iter.this_arg_index) {
            //case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:  printf("IEEE80211_RADIOTAP_DBM_ANTSIGNAL %i\n", *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_ANTENNA:        printf("IEEE80211_RADIOTAP_ANTENNA %i\n",       *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_TSFT:           printf("IEEE80211_RADIOTAP_TSFT %i\n",          *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_FLAGS:          printf("IEEE80211_RADIOTAP_FLAGS 0x%X\n",       *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_RATE:           printf("IEEE80211_RADIOTAP_RATE %i\n",          *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_CHANNEL:        printf("IEEE80211_RADIOTAP_CHANNEL 0x%X\n",       *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_RX_FLAGS:       printf("IEEE80211_RADIOTAP_RX_FLAGS 0x%X\n",    *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_TIMESTAMP:      printf("IEEE80211_RADIOTAP_TIMESTAMP 0x%X\n",     *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_MCS:            printf("IEEE80211_RADIOTAP_MCS 0x%X\n",           *(iter.this_arg));break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:   printf("IEEE80211_RADIOTAP_AMPDU_STATUS 0x%X\n",  *(iter.this_arg));break;
            //default:printf("Uncatched frame [%i]\n ", iter.this_arg_index);
        }       
    }
    printf("\n");**/

    // get packets //https://man.freebsd.org/cgi/man.cgi?query=radiotap&apropos=0&sektion=9&manpath=FreeBSD+11-current&format=html
    while(ieee80211_radiotap_iterator_next(&iter)==0){
        switch (iter.this_arg_index) {
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                dbm_antsignal_sum += (int)*(iter.this_arg)-256;
                measure_count++;
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                antenna_index |= 1<<(uint8_t) *(iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_TSFT:
                tsft = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                flags = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_RATE:
                data_rate = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_CHANNEL:
                channel = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_RX_FLAGS:
                rx_flag = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_TIMESTAMP:
                timestamp = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_MCS:
                mcs = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:
                ampdu_status = (uint64_t)* (iter.this_arg);
                break;
            default:
                printf("Uncatched frame [%i]\n ", iter.this_arg_index);
        }
    }
    if (measure_count == 0) return;//empty/invalid iterator
    
    printf("%s,%i,%i,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", 
    BSSID, 
    dbm_antsignal_sum/measure_count, 
    measure_count, 
    antenna_index, 
    channel, 
    tsft, 
    flags, 
    data_rate, 
    rx_flag, 
    timestamp, 
    mcs, 
    ampdu_status);
}


int main(int argc, char **argv) {
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    pcap_if_t* alldevs;
    

    for(argc; argc--;) {
        printf("%i,%s\n",argc, *(argv+argc));
    }
    if(pcap_findalldevs(&alldevs, errbuf)) {
        printf("%s\n",errbuf);
        exit(1);
    }
    dev = alldevs->name;
    printf("Device:,%s\n",dev);

    printf("=== Transmission ===\n");
    printf("SSID,BSSID,RSSI,COUNT,antenna_index,channel,TSFT,flags,data_rate,rx_flag,timestamp,mcs,ampdu_status\n");

    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    pcap_loop(descr,NB_FRAME,my_callback,NULL);

    return 0;
}
