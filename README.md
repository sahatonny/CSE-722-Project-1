# 🔐 Secure Chat Application – CSE722 Project 1

This is a two-user encrypted chat application built for the **CSE722: Security course**. It enables secure communication between two users using:

- 📡 TCP sockets for messaging
- 🔑 RSA for public key exchange
- 🧪 AES-256-CBC for encrypted messaging
- 🕵️ Packet capture using Wireshark for protocol validation

---

## 🧠 Project Objectives

- Create a working chat app using TCP
- Securely exchange RSA public keys
- Share an AES-256 key encrypted with RSA
- Send/receive messages encrypted with AES
- Capture traffic in Wireshark to verify encryption

---

## 📁 Project Structure

- server.py ( Runs the server-side chat application )
- client.py ( Runs the client-side chat application )
- Screenshots ( Screenshots of packet captured using Wireshark )
- README.md ( This file )


---

## 🚀 How to Run

### 📌 Requirements

- Python 3.6+
- Install required library:
  ```bash
  pip install pycryptodome

🖥️ Step 1: Start the Server
In one terminal:
 -```bash
  python server.py

💻 Step 2: Start the Client
In another terminal:
- ```bash
  python client.py
When prompted:
- ```nginx
  Enter Server IP: 127.0.0.1
(Use actual IP if on different machines.)

💬 Chat Commands
Command	Description
- ```yaml
  /key	-Generate and exchange RSA public keys
  /aes	-Share AES-256 key encrypted with RSA
  /exit	-Exit the chat
  (message)	-Send message (encrypted after /aes)

🔍 Wireshark Demonstration
Use Wireshark to capture and verify:
- ```yaml
  Packet Type	How to Capture
  Plaintext	Send message before /aes
  Encrypted	Send message after /aes

📖 Protocol Overview
TCP connection established between server and client.

Users exchange RSA public keys (/key).

AES key is generated and securely shared (/aes).

All messages are encrypted with AES-256-CBC after key exchange.

👩‍💻 Contributors
  - Name: Tanusree Saha Tanny
  - ID: 1000055884
  - Course: CSE 722



