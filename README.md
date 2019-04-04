# 2IC80-Project

# What is this?

This is a tool used to automatically ARP poison hosts on the local network, as well as DNS spoof them at the same time.

It has options for selecting interfaces, whitelisting certain hosts, DNS spoofing specific domains, or all.
The idea is to improve the semi-automatic approach of Ettercap. This tool can redirect local traffic visiting `www.example.com` to any IP address specified by the attacker. Furthermore, the attacker can perform a Man-in-the-Middle (MitM) attack on any of the intercepted packages.

# Prerequisites

The tool has been developed for a Linux environment.

In order to use the tool python 3.7 or higher must be installed:
 - [Python 3.7](https://www.python.org/downloads/release/python-370/)
 
Any other version might work as well, but has not been tested.
 
Please ensure that during the installation of Python, the option to add Python to the PATH environment is checked.

 [PIP](https://pip.pypa.io/en/stable/installing/) must also be installed.

The following packages are required to run code:
- scapy
- IPy

You can install each package seperately by executing:
```
python -m pip install [Package_to_install]
```
Or you can run the following command in the 2IC80-Project folder:
```
python -m pip install -r requirements.txt
```

# Running the tool

In the 2IC80-Project folder run the following command: ``python main.py``

Any options that can be specified will be prompted during the execution.

# Notes
Please note that ``python`` is sometimes also referenced as ``py``, ``python3`` or ``py3`` depending on your installation.

If any packages fail to be installed, please check the error thrown by pip
