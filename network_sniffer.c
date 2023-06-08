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

//nb of frames per set (-1 is infinity)
#define NB_FRAME 2000

//header frame for ieee80211 protocol 
struct ieee80211_header {
  u_short frame_control;
  u_short frame_duration;
  u_char address1[6];
  u_char address2[6];
  u_char address3[6];
  u_short sequence_control;
  u_char address4[6];
};

//callback called for each new transmission
void my_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    // get radiotap header
    struct ieee80211_radiotap_header* rtap_hdr = ( struct ieee80211_radiotap_header *) packet;
    if(rtap_hdr->it_version != 0) return;// check version it is not a 0 it's not radiotap
    
    // start iterator
    struct ieee80211_radiotap_iterator iter;
    int err = ieee80211_radiotap_iterator_init(&iter, rtap_hdr, pkthdr->caplen, NULL);
    if (err) return;

    //get ieee80211 header
    struct ieee80211_header* wifi_hdr = (struct ieee80211_header *) ( packet + iter._max_length);
    if(! (wifi_hdr->frame_control & (0b11<<6)) == (0b10<<6)) return;// Filter only FromDS=0, ToDS=1

    // get source informations
    char BSSID[18];
    int dbm_antsignal_sum = 0; //RSSI
    int measure_count = 0;
    uint32_t antenna_index = 0;
    uint16_t channel = -1;
    uint64_t tsft = -1;
    uint8_t flags = -1;
    uint8_t data_rate = -1;
    int rx_flag = -1;
    uint64_t timestamp = -1;
    uint32_t mcs = -1;
    uint32_t ampdu_status = -1;

    // get readable mac address
    sprintf(BSSID, "%02X:%02X:%02X:%02X:%02X:%02X", wifi_hdr->address2[0], wifi_hdr->address2[1], wifi_hdr->address2[2], wifi_hdr->address2[3], wifi_hdr->address2[4], wifi_hdr->address2[5]);
    
    // get packets //https://man.freebsd.org/cgi/man.cgi?query=radiotap&apropos=0&sektion=9&manpath=FreeBSD+11-current&format=html
    while(ieee80211_radiotap_iterator_next(&iter)==0){
        switch (iter.this_arg_index) {
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                dbm_antsignal_sum += (int)*(iter.this_arg)-256;
                measure_count++;
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                antenna_index |= 1<<(int)*(iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_TSFT:
                tsft = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                flags = (uint8_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_RATE:
                data_rate = (uint8_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_CHANNEL:
                channel = (uint16_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_RX_FLAGS:
                rx_flag = (int)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_TIMESTAMP:
                timestamp = (uint64_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_MCS:
                mcs = (uint32_t)* (iter.this_arg);
                break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:
                ampdu_status = (uint32_t)* (iter.this_arg);
                break;
            default:
                printf("Uncatched frame [%i]\n ", iter.this_arg_index);
        }
    }
    if (measure_count == 0) return;//empty/invalid iterator
    
    printf("%s,%i,%i,%u,%u,%lu,%u,%u,%i,%lu,%u,%u\n", BSSID, dbm_antsignal_sum/measure_count, measure_count, antenna_index, channel, tsft, flags, data_rate, rx_flag, timestamp, mcs, ampdu_status);
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
    printf("BSSID,dB_mean,measure_count,antenna_index,channel,TSFT,flags,data_rate,rx_flag,timestamp,mcs,ampdu_status\n");

    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    pcap_loop(descr,NB_FRAME,my_callback,NULL);

    return 0;
}
