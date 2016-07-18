#!/bin/bash
gnome-terminal -x bash -c "python sniffer_rest.py 5000 &"
gnome-terminal -x bash -c "sudo python sniffer.py" 
