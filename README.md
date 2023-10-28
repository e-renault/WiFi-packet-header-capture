# Positionnement_WiFi


## Data extraction
This git contains tools to extract, store, parse and preprocess wifi signals to get RSSI values from a specified position.


### Prerequise
In order to use thoses scripts, you should have to get:
 - A wifi card that allow wifi monitoring
 - the libradiotap library, see instructions : (github)[https://github.com/radiotap/radiotap-library] or `git submodule update --init`

 - (optional) airmon-ng, if wifi start.sh isn't sufficient to enable monitor mode) (see: (airmon-ng)[https://www.aircrack-ng.org/doku.php?id=airmon-ng]

### How to compile
You must compile including the radiotap-library AND add -lradiotap flag.

`gcc network_sniffer.c -I radiotap-library -lradiotap -lpcap -DNB_FRAME=10`

radiotape-library folder should be at the root of the project folder (same as network_sniffer.c)

### Execute
First enable monitor mode:
`sudo ./start.sh`

Then start scrapping:
`sudo ./a.out 1 2 3`
"xyz: 0 0 0": replace with you own coordinates. tee data/000.csv is for saving data to file, and can be changed

Recover to monitored mode (normal default mode):
`sudo ./stop.sh`

### Parse data
This is a basic script to extract and reduce datas
`Python3 converter.py file1 file2 ...`

Currently it doesn't save anything. You can input multiples files.
