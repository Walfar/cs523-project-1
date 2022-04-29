
#!/bin/bash

# This script queries every cell grid once . The argument is the directory name 
# in which to store the packets capture inside the dir pcaps. 

# Create the directory if it does not already exist.
#-$(date +'%m-%d-%y_%T')
[ -d pcaps/query-$1 ] || mkdir -pv pcaps/query-$1


for i in {1..100}
  do
    echo i
    echo $i
    # Create the file name.
    fname="grid-$i"
    tcpdump -i lo 'port 9050' -w pcaps/query-$1/$fname.pcap &
    sleep 0.1
    python3 client.py grid -p key-client.pub -c attr.cred -r '' -T 'restaurant' -t $i > /dev/null
    sleep 1
    kill "$!"   # kills the background process
  done