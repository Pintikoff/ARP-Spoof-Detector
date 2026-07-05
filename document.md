# GhostOnWire — ARP Security Toolkit: Offensive & Defensive Perspectives

## Legal Notice

**WARNING:** Unauthorized network attacks — including ARP spoofing, packet interception, and man-in-the-middle (MITM) exploitation — are illegal under computer misuse laws worldwide, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and similar legislation in other jurisdictions. These techniques may only be employed on networks you own or have explicit written authorization to test. Unauthorized use constitutes a criminal offense and may result in prosecution, fines, and imprisonment. The authors assume no liability for misuse of this material.

---

## Table of Contents

1. [Overview](#overview)
2. [Offensive Perspective](#offensive-perspective)
3. [Defensive Perspective](#defensive-perspective)
4. [Enterprise NAC and Prevention](#enterprise-nac-and-prevention)
5. [Commercial IDS/IPS Detection Techniques](#commercial-idsips-detection-techniques)
6. [Comparison with Industry Tools](#comparison-with-industry-tools)
7. [Key Concepts Learned](#key-concepts-learned)
8. [Deliverables](#deliverables)

---

## Overview

GhostOnWire is a dual-purpose ARP security toolkit comprising an offensive ARP spoofer and a real-time ARP spoof detection engine. It operates at Layer 2 of the OSI model using Scapy for packet manipulation and Rich for terminal-based dashboarding. The tool was developed to demonstrate ARP protocol vulnerabilities and to build practical detection mechanisms against the most common MITM attack vector in local networks.

---

## Offensive Perspective

### ARP Cache Poisoning

The offensive component (`spoofer.py`) implements bidirectional ARP cache poisoning. The spoofer sends forged ARP replies to both the victim and the gateway, causing each to associate the attacker's MAC address with the other's IP. This Places the attacker as an invisible intermediary in the communication path.

**Technique:**
- The victim's ARP cache is poisoned to map the gateway IP to the attacker's MAC.
- The gateway's ARP cache is poisoned to map the victim IP to the attacker's MAC.
- All traffic between victim and gateway now transits through the attacker's machine.
- IP forwarding must be enabled on the attacker to prevent connection drops.

### MAC Address Spoofing

The toolkit can forge MAC addresses with automatic vendor OUI identification, allowing the attacker to evade MAC-based access controls and obscure their hardware identity during reconnaissance.

### Passive Reconnaissance

Before launching an attack, the toolkit performs passive network discovery by sniffing ARP traffic to map active hosts, their MAC addresses, and vendors — all without sending a single packet.

---

## Defensive Perspective

### Real-Time ARP Spoof Detection

The defensive component (`detection.py`) continuously monitors ARP traffic and flags anomalies:

1. **Trusted Baseline Establishment** — An initial active ARP scan builds a ground-truth mapping of IP-to-MAC bindings. This serves as the reference for all subsequent comparisons.

2. **In-Memory Cache** — To avoid ARP request flooding (which both degrades network performance and draws attention), the detector maintains an in-memory cache loaded from the baseline table. The cache is updated only when the table file changes.

3. **Per-Packet Verification** — Every captured ARP reply is checked against the cache. A mismatch between the packet's source MAC and the cached MAC triggers a spoofing alert.

4. **Persistent Alerting** — Warnings persist for the duration of the session once triggered, even if the attacker later sends legitimate packets to cover their tracks.

5. **New Host Discovery** — The detector can discover new hosts that appear after the initial scan by falling back to a single, targeted ARP request when an IP is absent from the cache.

---

## Enterprise NAC and Prevention

Network Access Control (NAC) is the primary enterprise defense against ARP spoofing and Layer 2 attacks. The following mechanisms are employed:

### 802.1X Port-Based Authentication

Before a device is granted access to the network, it must authenticate via 802.1X using credentials or a certificate. Unauthenticated devices are placed in a restricted VLAN or blocked entirely. This prevents rogue devices from participating in ARP manipulation.

### Dynamic ARP Inspection (DAI)

DAI, commonly available on Cisco switches, intercepts all ARP packets on untrusted ports and verifies them against a DHCP snooping binding table before forwarding. ARP replies with invalid IP-to-MAC bindings are dropped without reaching their target.

### DHCP Snooping

Switches track which IP addresses have been assigned to which switch ports via DHCP. This binding table is used by DAI and IP Source Guard to validate traffic at the port level, preventing ARP spoofing from non-DHCP-assigned addresses.

### IP Source Guard

Filters traffic on a per-port basis, allowing only packets whose source IP matches the entry in the DHCP snooping binding table. This prevents IP address spoofing at Layer 3, which is often a prerequisite for ARP-based attacks.

### Private VLANs

Isolate ports within the same broadcast domain, preventing hosts on the same VLAN from communicating directly. All inter-host traffic must traverse a gateway where ACLs and inspection can be applied, eliminating the ARP spoofing surface between endpoints.

### Port Security

Limits the number of MAC addresses allowed on a single switch port. If an attacker attempts to flood ARP replies with different MAC addresses, the port is disabled or placed in an error-disabled state.

---

## Commercial IDS/IPS Detection Techniques

Commercial intrusion detection and prevention systems (e.g., Snort, Suricata, Cisco Firepower, Palo Alto Networks) employ several methods to detect ARP spoofing:

### ARP Anomaly Detection

Signature-based rules flag unusual ARP activity patterns:

- **ARP Flooding** — Detection of an abnormally high rate of ARP request/reply packets from a single source, indicative of scanning or poisoning.
- **ARP Sweep** — Multiple ARP requests to sequential IP addresses in short succession, signaling reconnaissance.
- **Gratuitous ARP Monitoring** — Detection of gratuitous ARP replies (unsolicited broadcasts) that change a known IP-to-MAC binding.

### Cross-Layer Correlation

The IDS correlates ARP activity with observations from other layers:

- **IP-to-MAC Binding Changes** — If a host's MAC changes mid-session while the IP remains the same, this is flagged as suspicious.
- **Duplicate IP Detection** — Multiple MAC addresses claiming the same IP address in ARP traffic triggers an immediate alert.

### Statistical Profiling

Behavioral analysis engines build baselines of normal ARP traffic patterns per host and segment. Deviations — such as a previously quiet host suddenly sending many ARP replies — are scored and escalated.

### Integration with DHCP Logs

ARP bindings are cross-referenced against DHCP server leases. An ARP reply that claims an IP not issued by the DHCP server is immediately flagged as spoofed.

### MAC Address Validation

Checks for MAC address anomalies:

- Multicast or broadcast MACs used as source addresses.
- MAC OUIs that do not match the expected manufacturer for a given device type.
- MAC addresses with all-zero or suspicious patterns.

### Alert Generation and Automated Response

On detecting spoofing, commercial systems can:

- Generate real-time alerts with full packet capture context.
- Automatically create ACL entries to block the offending MAC/IP.
- Trigger NAC re-authentication for the affected switch port.
- Log the event to a SIEM for correlation with other network telemetry.

---

## Comparison with Industry Tools

### arpspoof (part of dsniff suite)

| Feature | arpspoof | GhostOnWire |
|---------|----------|-------------|
| Attack Type | Bidirectional MAC spoofing | Bidirectional MAC spoofing |
| Defensive Mode | None | Real-time detection engine |
| Reconnaissance | Requires manual scanning | Built-in active/passive scanning |
| Output | Console messages | Rich TUI dashboard |
| Vendor Lookup | No | Yes (OUI database) |
| Timestamp Tracking | No | First/last seen per host |
| Alert Persistence | N/A | Persistent session warnings |
| IP Forwarding | Requires manual enable | Manual enable |
| Cache Flooding Prevention | N/A | In-memory cache with fallback |

### Ettercap

| Feature | Ettercap | GhostOnWire |
|---------|----------|-------------|
| Attack Modes | ARP, DHCP, DNS spoofing | ARP spoofing only |
| Defensive Mode | Built-in ARP monitor | Dedicated detection engine |
| Plugin System | Extensive | None (modular Python) |
| Filters & Content Injection | Yes | No |
| TLS/SSL Stripping | Yes | No |
| TUI Dashboard | curses-based | Rich-based with colored tables |
| Ease of Extension | Limited by plugin API | Direct Python modification |
| Cross-Platform | Linux/BSD/macOS | Windows (targeted) |

### Bettercap

| Feature | Bettercap | GhostOnWire |
|---------|-----------|-------------|
| Attack Modules | ARP, DNS, DHCP, HTTPS, BLE, WiFi | ARP spoofing |
| Defensive Module | Event-based detection | Dedicated real-time detection |
| Scripting | Lua scripting engine | Direct Python |
| HTTP/HTTPS Proxy | Full proxy with HSTS bypass | None |
| Web UI | Built-in web interface | Terminal-based TUI |
| Module Ecosystem | Large, community-driven | Single-purpose |
| Resource Usage | Moderate (Go binary) | Lightweight (Python) |
| Learning Curve | Steep | Moderate |

### Summary

- **Bettercap** is the most feature-rich and modern offensive framework, ideal for red-team engagements.
- **Ettercap** offers the broadest protocol-level manipulation for established MITM attack chains.
- **arpspoof** is the simplest and most focused — a single-purpose tool for ARP poisoning.
- **GhostOnWire** fills a unique niche: it provides both offense and defense in a single, transparent Python codebase, making it ideal for **learning** ARP security concepts. Unlike the other tools, it is not designed for production red-teaming but for **education, demonstration, and understanding** the underlying mechanics.

---

## Key Concepts Learned

- **ARP protocol mechanics and vulnerabilities** — How ARP request/reply operates without authentication, making spoofing trivial.
- **MAC address structure and OUI vendor identification** — The first 24 bits of a MAC identify the manufacturer; Scapy's `manufdb` provides lookups.
- **Man-in-the-middle attacks at Layer 2** — By forging ARP replies, an attacker redirects traffic through their machine, intercepting or modifying it.
- **Scapy packet crafting and network interaction** — Using `ARP()`, `Ether()`, `srp()`, and `sniff()` to send, receive, and capture raw Layer 2 frames.
- **ARP spoof detection techniques** — Passive monitoring of MAC-IP bindings and comparing against a trusted baseline.
- **Network trust modeling** — Building a ground-truth ARP table via active scan and treating deviations as suspicious.
- **TUI dashboard development** — Using Rich's `Table` and `Console` for real-time terminal output with color-coded status.
- **Network Access Control (NAC)** — Mechanisms such as 802.1X, DAI, DHCP snooping, and port security that enterprises deploy to mitigate Layer 2 attacks.
- **Commercial IDS/IPS detection** — Signature-based, behavioral, and correlation-based detection of ARP anomalies.
- **Offensive-defensive duality** — Understanding both attack and defense provides a complete picture of the security landscape.

---

## Deliverables

- **MAC address spoofer with vendor OUI lookup** — Script capable of forging MAC addresses with manufacturer identification.
- **ARP cache poisoner with bidirectional MITM** — Tool to send forged ARP packets to both victim and gateway for full traffic interception.
- **Real-time ARP spoof detection engine** — The core detector in `detection.py` that monitors and alerts on spoofing.
- **Layer 2 network trust map with scoring** — Table of all discovered devices with IP, MAC, vendor, and temporal metadata.
- **TUI dashboard with offensive/defensive modes** — Interactive terminal interface displaying network state and security alerts.
- **Passive and active network reconnaissance** — Combining `sniff()` for passive monitoring with `srp()` for active host discovery.
