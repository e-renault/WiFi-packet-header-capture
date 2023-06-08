# wifi_positionning

## Prerequise
 - A wifi card that allow wifi monitoring
 - libradiotap library (see instructions : (github)[https://github.com/radiotap/radiotap-library])
 - (optional) airmon-ng (if wifi start.sh isn't sufficient to enable monitor mode) (see: (airmon-ng)[https://www.aircrack-ng.org/doku.php?id=airmon-ng])

## How to compile
You must compile including the radiotap-library AND add -lradiotap flag.

`gcc network_sniffer.c -I radiotap-library -lradiotap -lpcap`

## Execute
`sudo ./a.out "xyz: 0 0 0" | tee data/000.csv`
"xyz: 0 0 0": replace with you own coordinates. tee data/000.csv is for saving data to file, and can be changed

## Parse data
`Python3 converter.py file1 file2 ...`
