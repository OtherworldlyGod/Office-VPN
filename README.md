# Java VPN System (Custom VPN Server & Client)

A Java-based VPN simulation built using socket programming. The system includes a multi-protocol VPN server and a GUI client to demonstrate how VPN tunneling, authentication, virtual IP assignment, and NAT-like translation work internally.

---

## Project Overview

This project simulates a basic VPN environment entirely in Java without OS-level tunneling.  
Key concepts demonstrated:

- Protocol negotiation  
- Tunnel simulation  
- Client–server communication  
- User authentication  
- Virtual IP allocation  
- NAT-style packet handling  

---

## Features

### Supported Protocols
- OpenVPN  
- IPSec  
- WireGuard  
- CustomVPN  

Each protocol defines its own handshake and packet structure.

### Architecture
- TCP socket communication  
- Multithreaded server for concurrent clients  
- Swing-based GUI for both server and client  

### Authentication
User credentials are validated via a CSV file.  
A sample file `users.example.csv` is included.

### Virtual IP Assignment
An internal IP pool assigns virtual IPs (e.g., 10.0.0.x) to connected clients.

### NAT Simulation
Basic translation of internal VPN IPs to simulated external values.

---

## Project Structure

project/
├── src/
│ ├── VPNServerGUI.java
│ ├── VPNClientGUI.java
│ ├── protocol classes...
├── lib/
├── users.example.csv
├── README.md
└── .gitignore

yaml
Copy code

---

## How to Run

### Start the Server
javac src/VPNServerGUI.java
java src/VPNServerGUI


### Start the Client
javac src/VPNClientGUI.java
java src/VPNClientGUI


Choose a protocol, enter credentials, and connect.

---
