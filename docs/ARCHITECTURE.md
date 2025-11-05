# SDN-NIDPS System Architecture

## Overview

The **Software-Defined Networking-based Network Intrusion Detection and Prevention System (SDN-NIDPS)** is designed using a **multi-layered architecture**.
This architecture separates system concerns into **four distinct planes**, ensuring modularity, scalability, and ease of management.

### Architectural Planes

1.  **Data Plane** — Handles actual packet forwarding using network infrastructure (e.g., OVS switches, hosts).
2.  **Control Plane** — Implements SDN controller logic for managing network flow rules and routing.
3.  **Detection Plane** — Contains threat detection engines that analyze traffic for malicious activity.
4.  **Management Plane** — Provides the dashboard, APIs, and management interfaces for configuration and visualization.

-----

## Detailed Architecture

### 1\. Data Plane (Mininet / Open vSwitch)

This layer represents the **physical or virtual network topology**, consisting of hosts and Open vSwitch (OVS) switches.
It is responsible for **packet forwarding** and acts as the foundation on which other planes operate.

#### Example Network Topology

```text
┌─────────────────────────────────────────┐
│           Network Topology              │
│                                         │
│  ┌──────────┐      ┌──────────┐         │
│  │ Switch 1 │──────│ Switch 2 │         │
│  └──────────┘      └──────────┘         │
│      │ │                │ │             │
│    H1 H2              H3 H4             │
└─────────────────────────────────────────┘
```

Components:

  * **Switches (S1, S2):** Open vSwitch instances managed by the SDN controller.
  * **Hosts (H1–H4):** End devices generating or receiving traffic within the network.

-----

### 2\. Control Plane

The Control Plane provides **centralized intelligence** to the network through an **SDN Controller** (e.g., Ryu, ONOS, or Floodlight).
It manages flow rules, collects statistics, and enforces policies dynamically.

Functions:

  * Maintains a **global view** of the network.
  * Installs **flow entries** in OVS switches.
  * Interacts with the Detection Plane to isolate or block malicious traffic.

-----

### 3\. Detection Plane

This plane includes **Intrusion Detection and Prevention modules**, integrating tools such as **Snort, Suricata**, or custom ML-based engines.

Responsibilities:

  * Analyze mirrored or live traffic for potential threats.
  * Generate **alerts** for the Management Plane.
  * Notify the Control Plane to enforce countermeasures (e.g., block IPs, modify flow tables).

-----

### 4\. Management Plane

The Management Plane provides **system control, monitoring, and visualization** through:

  * Web Dashboard
  * RESTful APIs
  * Administrative Tools

Key Functions:

  * View **real-time alerts** and traffic analytics.
  * Configure IDS/IPS rules.
  * Monitor controller and network status.
  * Manage users and system policies.

-----

## Summary

The SDN-NIDPS architecture integrates traditional network security with the flexibility of SDN.
By separating detection and control logic from the data plane, it enables:

  * Centralized control
  * Automated threat response
  * Improved visibility
  * Easier scalability

-----
