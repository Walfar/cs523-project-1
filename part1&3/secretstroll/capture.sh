
#!/bin/bash

# This script makes n query where all the grids are queried each of the n times. Here n = 5 

for quer in {1..5}
   do
   echo query $quer
   for i in {1..100}
    do
      echo grid $i
      # Create the file name.
      fname="query-$quer-grid-$i"
      tcpdump -i lo 'port 9050' -w pcaps/$fname.pcap & #port 9050 is used for Tor
      sleep 0.1
      python3 client.py grid -p key-client.pub -c anon.cred  -T 'restaurant' -t $i > /dev/null
      sleep 1
      kill "$!"   # kills the background process
    done

   done 

