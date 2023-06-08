#! /usr/bin/python3
import pandas as pd
import matplotlib.pyplot as plt
import re
import sys

# Global datas
x,y,z = (0, 0, 0)

def extract_metadata(filename):
    global x,y,z
    skip_rows = 0
    with open(filename, 'r') as file:
        for line in file:
            skip_rows += 1

            if line.startswith('=== Transmission ==='):
                break

            keyword_location = 'xyz:'
            coord = line.find(keyword_location)
            if coord != -1:
                c = re.findall(r'\b\d+\b', line)
                print(c)
                x, y, z = (c[1], c[2], c[3])

def extract_clean_dataset(filename):
    skip_rows = 0
    with open(filename, 'r') as file:
        for line in file:
            skip_rows += 1
            if line.startswith('=== Transmission ==='):
                break

    df = pd.read_csv(filename, skiprows=skip_rows)
    df.columns = df.columns.map(lambda x: x.strip()) #remove spaces, tabs, etc, that could be produced by term
    df = df[:-1] #delete last line (usually corrupted due to abrupt stops)
    return df

def convert_dataset(df):
    global x,y,z
    agg = df.groupby('BSSID').aggregate({
        'dB_mean': 'mean',
        'measure_count': 'sum',
        'antenna_index': 'unique', 
        'channel': 'unique', 
        'TSFT': 'unique',
        'flags': 'unique', 
        'data_rate': 'unique', 
        'rx_flag': 'unique', 
        'timestamp': 'median',
        'mcs': 'unique',
        'ampdu_status': 'unique',
    })

    agg['x'] = x
    agg['y'] = y
    agg['z'] = z

    return agg
    
def main():
    argc = len(sys.argv)
    if argc < 2:
        print("Please provide at least one file")
        exit(1)
    
    for filename in sys.argv[1:]:
        extract_metadata(filename)
        df = extract_clean_dataset(filename)
        agg = convert_dataset(df)

        agg = agg.sort_values(by=['dB_mean'], ascending=False)
        print(agg.head(40))
        agg.plot(kind = 'bar', y = 'dB_mean')
        plt.show()

if __name__ == "__main__":
    main()