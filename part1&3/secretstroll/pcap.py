from scapy.all import *
import numpy as np
import csv
import sys
import os
import re

"""
Once we have all the data available, we first need to run pcap.py save to aggregate and save the data in the corresponding csv file
then we can call the other functions, i.e. to load the folds of data to train the classifier.
"""

def filter():
    '''
    Output the name of incomplete capture file, i.e those who do not have all PoIs answers. This is checked by counting that the number of HTTP 200 OK is equal to the number of PoIs + 1 for the complete list. 
    WARNING : This function is not robust at all and will fail if there are non pcap file in the data folder. It was used to check the correctness of the collected data.
    It also needs scapy (pip3 install scapy).
    '''
    #None to account cell number from 1 to 100
    nb_poi = [None, 11, 14, 13, 5, 11, 6, 10, 12, 8, 5, 12, 9, 12, 9, 14, 11, 15, 10, 10, 7, 6, 10, 9, 10, 15, 13, 8, 8, 12, 8, 11, 8, 7, 9, 7, 15, 11, 12, 11, 3, 15, 7, 8, 14, 12, 10, 11, 6, 7, 8, 14, 9, 9, 5, 9, 11, 13, 10, 7, 12, 12, 11, 8, 15, 10, 11, 8, 6, 13, 12, 9, 6, 14, 13, 11, 4, 14, 9, 9, 10, 10, 17, 13, 16, 3, 11, 9, 15, 6, 5, 8, 10, 6, 7, 8, 12, 14, 5, 13, 13]

    nb_file = 0
    for file in os.listdir("pcaps"):

        nb = 0
        cell_id = 0

        packets = rdpcap("pcaps/"+file)

        for pkt in packets:
            if pkt[TCP].payload:
                #Look for the cell id
                i = pkt[TCP].load.decode('utf-8').find("cell_id=")
                if i != -1:
                    cell_id = re.search(r'\d+',pkt[TCP].load.decode('utf-8')[i:]).group()
                    break
        for pkt in packets:
            if pkt[TCP].payload:
                #count the number of OK response
                if "HTTP/1.0 200 OK" in pkt[TCP].load.decode('utf-8'):
                    nb += 1
        print(int(cell_id))
        print(type(cell_id))
        if nb_poi[int(cell_id)] +1 != nb:
            print(file)
            nb_file += 1

    print(nb_file)

def aggregate():
    """
    Return the loaded, derived and aggregated data from all the pcap files in a dictionary whose keys correspond to the IDs
    and the values are lists of truncated lists containing the values of the bytes of at most 400 packets header whose lenght is 66.
    """

    datas = {}  

    for n in range(1,101):
        datas[str(n)] = []

    for file in os.listdir("data"):
        packets = rdpcap("data/"+file)
        for pkt in packets:
            if pkt[TCP].payload:
                i = pkt[TCP].load.decode('utf-8').find("cell_id=")
                if i != -1:
                    cell_id = re.search(r'\d+',pkt[TCP].load.decode('utf-8')[i:]).group()
                    break
            
        lens = []
        for pkt in packets:
            pkt[TCP].remove_payload()
            l = len(raw(pkt))
            if l == 66:
                for b in raw(pkt):
                    lens.append(str(b))
        if len(lens) > 400 * 66:
            lens = lens[:400 * 66]
        datas[cell_id].append(lens)
    return datas

def save_aggregate():
    """
    Save the aggregated data in a packets_lens.csv file whose rows are of the form "ID DATA"
    """

    print("aggregating data...")
    a = aggregate()

    print("saving...")
    with open("packets_lens.csv", "w", newline="") as csvfile:
        fieldnames = ["id", "lens"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=" ")

        writer.writeheader()
        for k,v in a.items():
            for i in v:
                writer.writerow({"id": k, "lens":";".join(i)})

    print("saved successfully")

def load_aggregate():
    """
    Load the aggregated data saved in the packets_lens.csv file and
    return x the DATAs and y the corresponding IDs as well as max_l the maximum number of features in x
    """

    x, y = [], []
    max_l = -1

    with open("packets_lens.csv", newline="") as csvfile:
        reader = csv.reader(csvfile, delimiter=" ")
        h = next(reader)
        for r in reader:
            i, l = r
            i, l = int(i), [float(t) for t in l.split(";")]
            y.append(i)
            x.append(l)
            max_l = max(max_l, len(l))

    return x, y, max_l

def indices(y):
    """
    Return a list of 10 lists containing the indices of the permutations to create
    10 folds for the corresponding y long dataset
    """

    np.random.seed(1)
    num_row = len(y)
    interval = int(num_row / 10)
    indices = np.random.permutation(num_row)

    return [indices[k * interval: (k + 1) * interval] for k in range(10)]


def load_folds():
    """
    Return a 10 folds list of the data loaded with load_aggregate() and indices derives with indices(y)
    in x_folds for DATA and y_folds for ID, max_l contains the number of features of each value in x
    """

    x, y, max_l = load_aggregate()
    for i in range(len(x)):
        x[i] = x[i]+[0]*(max_l-len(x[i]))

    x, y = np.array(x), np.array(y)

    x_folds, y_folds = [], []
    i_s = indices(y)

    for i in i_s:
        x_folds.append(x[i].tolist())
        y_folds.append(y[i].tolist())

    return x_folds, y_folds, max_l

if __name__ == "__main__":
    if sys.argv[1] == "filter":
        filter()
    elif sys.argv[1] == "save":
        save_aggregate()
    else:
        print("unrecognized command! Use filter or save")