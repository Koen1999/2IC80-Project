# 2IC80-Project

# What is this?

This is a tool used to automatically ARP poison hosts on the local network, as well as DNS spoof them at the same time.

It has options for selecting interfaces, whitelisting certain hosts, DNS spoofing specific domains, or all.
The idea is to improve the semi-automatic approach of Ettercap. This tool can redirect local traffic visiting `www.example.com` to any IP address specified by the attacker. Furthermore, the attacker can perform a Man-in-the-Middle (MitM) attack on any of the intercepted packages.


You can find a short demo of the tool here: 

[![2IC80-Project Demo](https://i.ytimg.com/vi/Vbff_NE_RN0/hqdefault.jpg?sqp=-oaymwEjCPYBEIoBSFryq4qpAxUIARUAAAAAGAElAADIQj0AgKJDeAE=&rs=AOn4CLDoX8OeNvVGShUI0lIb188gOVDTjw)](https://youtu.be/Vbff_NE_RN0)

# Prerequisites

The tool has been developed for a Linux environment.

In order to use the tool python 3.7 or higher must be installed:
 - [Python 3.7](https://www.python.org/downloads/release/python-370/)
 
Any other version might work as well, but has not been tested.

 [PIP](https://pip.pypa.io/en/stable/installing/) must also be installed.

The following packages are required to run code:
- scapy
- IPy

You can run the following command in the 2IC80-Project folder to install all required packages:
```
python -m pip install -r requirements.txt
```

# Running the tool

In the 2IC80-Project folder run the following command: ``python main.py``

Any options that can be specified will be prompted during the execution.
