import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

public_key_other = None
rsa_key = None
aes_key = None

def send_aes_key(conn):
    global aes_key
    if public_key_other is None:
        print("[!] Cannot send AES key — no public key received yet.")
        return

    aes_key = get_random_bytes(32)
    cipher_rsa = PKCS1_OAEP.new(public_key_other)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    encoded_key = base64.b64encode(encrypted_key).decode()

    conn.send(f"[AES_KEY]{encoded_key}".encode())
    print("[*] AES key encrypted and sent.")


def handle_receive(conn):
    global public_key_other
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break

            if data.startswith("[KEY]"):
                key_data = data[5:].strip()
                public_key_other = RSA.import_key(base64.b64decode(key_data))
                print("[*] Public key received and stored.")
            elif data.startswith("[AES_KEY]"):
                encrypted = base64.b64decode(data[9:].strip())
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                aes_key = cipher_rsa.decrypt(encrypted)
                print("[*] AES key received and stored.")
            elif data.startswith("[ENCRYPTED]"):
                if aes_key is None:
                    print("[!] Encrypted message received but AES key not available.")
                else:
                    decrypted = decrypt_message(data[11:].strip(), aes_key)
                    print(f"[Client] {decrypted}") 
            else:
                print(f"[Client] {data}")
            

        except Exception as e:
            print("Receive error:", e)
            break

def send_public_key(conn):
    global rsa_key
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key()
    message = "[KEY]" + base64.b64encode(public_key).decode()
    conn.send(message.encode())
    print("[*] Public key sent.")

def encrypt_message(msg, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(msg.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()

def decrypt_message(data, key):
    try:
        raw = base64.b64decode(data)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except:
        return "[Decryption Failed]"

def main():
    global rsa_key
    host = '0.0.0.0'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"[+] Server listening on port {port}...")
    conn, addr = server_socket.accept()
    print(f"[+] Connected with {addr}")

    threading.Thread(target=handle_receive, args=(conn,), daemon=True).start()

    while True:
        msg = input()

        if msg.lower() == '/exit':
            break
        elif msg.lower() == '/key':
            send_public_key(conn)
        elif msg.lower() == '/aes':
            send_aes_key(conn)
        elif aes_key:
            encrypted = "[ENCRYPTED]" + encrypt_message(msg, aes_key)
            conn.send(encrypted.encode())
        else:
            conn.send(msg.encode())

    conn.close()
    server_socket.close()
    print("[*] Server shutdown.")

if __name__ == "__main__":
    main()
