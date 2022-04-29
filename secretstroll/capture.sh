
#!/bin/bash

# This script queries every cell grid once . The argument is the directory name 
# in which to store the packets capture inside the dir pcaps. 

# Create the directory if it does not already exist.
#-$(date +'%m-%d-%y_%T')

for quer in {1..5}
   do
   echo query $quer
   [ -d pcaps/query-$quer ] || mkdir -pv pcaps/query-$quer
   for i in {1..100}
    do
      echo grid $i
      # Create the file name.
      fname="grid-$i"
      tcpdump -i lo 'port 9050' -w pcaps/query-$quer/$fname.pcap & #port 9050 is used for Tor
      sleep 0.1
      python3 client.py grid -p key-client.pub -c anon.cred  -T 'restaurant' -t $i > /dev/null
      sleep 1
      kill "$!"   # kills the background process
    done

   done 

