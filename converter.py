#! /usr/bin/python3
import pandas as pd
import matplotlib.pyplot as plt
import re
import sys

def extract_clean_dataset(filename):
    df = pd.read_csv(filename)
    df.columns = df.columns.map(lambda x: x.strip()) #remove spaces, tabs, etc, that could be produced by term
    return df

def mac_to_int(mac_address):
    hex_parts = mac_address.split(':')
    hex_string = ''.join(hex_parts)
    return int(hex_string, 16)

def convert_dataset(df):
    df2 = df.groupby(['SA', 'x', 'y', 'z']).aggregate({
        'RSSI': 'mean',
        'COUNT': 'sum',
        'SSID': 'unique', 
        'BSSID': 'unique', 
        'DA': 'unique', 
        'antenna_index': 'unique', 
        'channel': 'unique', 
        'TSFT': 'unique',
        'flags': 'unique', 
        'data_rate': 'unique', 
        'rx_flag': 'unique', 
        'timestamp': 'median',
        'mcs': 'unique',
        'ampdu_status': 'unique',
    }).reset_index()

    return df2

def pivotDataset(df):
    df['SA'] = df['SA'].apply(mac_to_int)

    agg = pd.pivot_table(df, values='RSSI', index=['x', 'y'], columns=['SA'], fill_value=-99)

    return agg

def main():
    argc = len(sys.argv)
    if argc < 2:
        print("Please provide at least one file")
        exit(1)
    
    df = extract_clean_dataset(sys.argv[1])
    agg = convert_dataset(df)

    if argc < 3:
        print("No output file found, please provide one")
        exit(1)
    agg.to_csv(path_or_buf=sys.argv[2],index=False)



if __name__ == "__main__":
    main()