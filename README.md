# ARP-Spoof-Detector

## Overview
[Offensive_Defensive_Documentation](Offensive_Defensive_Guide.md)
GhostOnWire is a dual-purpose ARP security toolkit comprising an offensive ARP spoofer and a real-time ARP spoof detection engine. It operates at Layer 2 of the OSI model using Scapy for packet manipulation and Rich for terminal-based dashboarding. The tool was developed to demonstrate ARP protocol vulnerabilities and to build practical detection mechanisms against the most common MITM attack vector in local networks.

---

**WARNING:** Unauthorized network attacks — including ARP spoofing, packet interception, and man-in-the-middle (MITM) exploitation — are illegal under computer misuse laws worldwide, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and similar legislation in other jurisdictions. These techniques may only be employed on networks you own or have explicit written authorization to test. Unauthorized use constitutes a criminal offense and may result in prosecution, fines, and imprisonment. The authors assume no liability for misuse of this material.

---

## Dependencies

```bash
pip install -r requirements.txt
```

## Run the programm 

Simply run it with python3

```bash
python3 detection.py
python3 spoofer.py
```
