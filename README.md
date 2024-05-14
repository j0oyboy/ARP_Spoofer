# ARP Spoofer

## Overview
This ARP spoofer is a tool designed for network penetration testing and security assessment purposes. It allows the user to intercept and modify ARP (Address Resolution Protocol) messages on a local area network, enabling various types of attacks such as Man-in-the-Middle (MITM) attacks.

## Features
- **ARP Spoofing**: Spoof ARP messages to redirect traffic through the attacker's machine.
- **Man-in-the-Middle (MITM) Attacks**: Intercept and modify traffic between two hosts on the same network.
- **Network Restoration**: Restore the network to its original state after the attack.

## Requirements
- Python 3.x
- Scapy library

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/souhaib-soo/ARP-Spoofer.git
    ```
2. Navigate to the project directory:
    ```bash
    cd ARP-Spoofer
    ```

## Usage
```bash
python ARP-Spoofer.py -t TARGET_IP -g GATEWAY_IP
```
## Arguments:
```bash
-t TARGET_IP, --target TARGET_IP: IP address of the target/victim machine.

-g GATEWAY_IP, --gateway GATEWAY_IP: IP address of the router/gateway.
```
## Example
```bash
python arp_spoofer.py -t 192.168.1.100 -g 192.168.1.1
```
## Disclaimer
This tool is intended for educational and ethical testing purposes only. Misuse of this tool for malicious activities is illegal and can lead to severe legal consequences. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.
