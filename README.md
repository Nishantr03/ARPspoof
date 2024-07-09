# CyberSecurity Network Security Tool

This is a Python-based network security tool with a graphical user interface (GUI) built using the `tkinter` library. The tool is designed to detect promiscuous mode and ARP poisoning in a network, giving it a cybersecurity vibe with a dark theme and relevant icons.

## Features

- **Promiscuous Mode Detection**: Detects if any network interface is in promiscuous mode.
- **ARP Poisoning Detection**: Detects ARP spoofing attacks on the network.
- **User-Friendly GUI**: A visually appealing interface with cybersecurity-themed styling and icons.

## Requirements

- Python 3.x
- Required Python libraries:
  - `tkinter`
  - `psutil`
  - `scapy`
  - `Pillow`
    
## Run the program 
- python project.py 

## Code Overview
- Main Interface
- The main interface is a tkinter window with a dark theme, a title, and buttons to open new windows for each detection feature.

- Promiscuous Mode Detection
- Opens a new window where you can enter an IP address to check if any device in the network is in promiscuous mode.

- ARP Poisoning Detection
- Opens a new window where you can select a network interface to detect ARP spoofing attacks.

## Functions
- get_mac(ip): Returns the MAC address of a given IP.
- process(packet): Processes packets to detect ARP spoofing.
- sniffs(e): Sniffs network packets to detect ARP poisoning.
- promiscs(e1): Checks if a device is in promiscuous mode.
- get_macs(ip): Sends a packet to detect promiscuous mode devices.



## Acknowledgements
- This project is based on the original code from the Detection of ARP spoofing and Promiscuous Mode repository by kuladeepmantri.
- The scapy library for packet manipulation.
- The Pillow library for handling images.
- The cybersecurity community for inspiration and support.
