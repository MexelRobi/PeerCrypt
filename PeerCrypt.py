import socket
import threading
import sys
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Fixed salt for key derivation function
SALT = b'\x84\xfa\xbc\x12\x0e\x99\x11\xe3'


def derive_key(password: str) -> bytes:
    """Derives a 32-byte AES key from the manually entered password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_message(message: str, key: bytes) -> str:
    """Encrypts a message using AES-256-CBC."""
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # PKCS7 padding
    padded_data = message.encode()
    pad_len = 16 - (len(padded_data) % 16)
    padded_data += bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine IV and ciphertext, then encode as Base64
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_message(encrypted_data_str: str, key: bytes) -> str:
    """Decrypts a message using AES-256-CBC."""
    try:
        data = base64.b64decode(encrypted_data_str.encode("utf-8"))

        if len(data) < 32:
            raise ValueError()

        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_padded = (
            decryptor.update(ciphertext) +
            decryptor.finalize()
        )

        # Remove PKCS7 padding
        pad_len = decrypted_padded[-1]

        if pad_len < 1 or pad_len > 16:
            raise ValueError()

        # Verify padding
        if decrypted_padded[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError()

        return decrypted_padded[:-pad_len].decode("utf-8")

    except Exception:
        return "[Error: Message could not be decrypted. Wrong key?]"


def receive_messages(sock, key):
    """Continuously receives and decrypts messages in a background thread."""
    while True:
        try:
            data = sock.recv(4096).decode("utf-8")

            if not data:
                print("\n[Partner disconnected.]")
                break

            decrypted = decrypt_message(data, key)

            print(f"\nPartner: {decrypted}")
            print("You: ", end="", flush=True)

        except Exception:
            print("\n[Connection lost.]")
            break

    os._exit(0)


def get_port():
    """Asks the user for a TCP port."""
    while True:
        port_input = input("Enter port [55555]: ").strip()

        # Use default port when nothing is entered
        if not port_input:
            return 55555

        try:
            port = int(port_input)

            if 1 <= port <= 65535:
                return port

            print("Port must be between 1 and 65535.")

        except ValueError:
            print("Please enter a valid number.")


def main():
    print("=== PeerCrypt: Encrypted P2P Temp Chat ===")

    # 1. Ask for encryption key
    password = input(
        "Enter secret chat key (must match your partner's key): "
    ).strip()

    if not password:
        print("Key cannot be empty!")
        return

    key = derive_key(password)

    # 2. Select connection mode
    mode = input(
        "Do you want to (1) Host or (2) Join? [1/2]: "
    ).strip()

    # 3. Select port
    port = get_port()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if mode == "1":
        # Host mode
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(1)

            print(f"\nWaiting for connection on port {port}...")
            print("Give your partner your IP address and this port.")

            conn, addr = sock.accept()

            print(f"Connected to {addr[0]}:{addr[1]}")

            # The listening socket is no longer needed
            sock.close()

        except OSError as e:
            print(f"Could not start server on port {port}: {e}")
            return

    elif mode == "2":
        # Client mode
        target_ip = input("Enter partner's IP address: ").strip()

        try:
            sock.connect((target_ip, port))

            conn = sock

            print(
                f"Successfully connected to "
                f"{target_ip}:{port}"
            )

        except Exception as e:
            print(f"Connection failed: {e}")
            sock.close()
            return

    else:
        print("Invalid choice.")
        sock.close()
        return

    # Start the receive thread
    threading.Thread(
        target=receive_messages,
        args=(conn, key),
        daemon=True
    ).start()

    # Main sending loop
    print(
        "\nChat started! Type a message and press Enter. "
        "(Type '/exit' to quit)\n"
    )

    while True:
        try:
            msg = input("You: ")

            if msg.lower() == "/exit":
                break

            if msg.strip() == "":
                continue

            encrypted = encrypt_message(msg, key)
            conn.sendall(encrypted.encode("utf-8"))

        except KeyboardInterrupt:
            break

        except (BrokenPipeError, ConnectionResetError):
            print("\n[Partner disconnected.]")
            break

    print("[Chat ended]")

    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
