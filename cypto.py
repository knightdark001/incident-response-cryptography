from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import hashlib

# Symmetric Encryption (AES)

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def aes_decrypt(key, data):
    raw_data = base64.b64decode(data)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Asymmetric Encryption (RSA)

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_sign(private_key, data):
    key = RSA.import_key(private_key)
    h = SHA256.new(data.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def rsa_verify(public_key, data, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(data.encode('utf-8'))
    signature = base64.b64decode(signature)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Hashing (SHA-256)

def hash_data(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# User Interaction

def main():
    while True:
        print("Choose an option:")
        print("1. AES Encryption")
        print("2. AES Decryption")
        print("3. RSA Key Generation")
        print("4. RSA Digital Sign")
        print("5. RSA Verify Signature")
        print("6. SHA-256 Hashing")
        print("7. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            key = input("Enter a 16-byte key: ").encode('utf-8')
            data = input("Enter data to encrypt: ")
            encrypted_data = aes_encrypt(key, data)
            print(f"Encrypted Data: {encrypted_data}")

        elif choice == '2':
            key = input("Enter a 16-byte key: ").encode('utf-8')
            data = input("Enter data to decrypt: ")
            decrypted_data = aes_decrypt(key, data)
            print(f"Decrypted Data: {decrypted_data}")

        elif choice == '3':
            private_key, public_key = generate_rsa_keys()
            print(f"Private Key: {private_key.decode('utf-8')}")
            print(f"Public Key: {public_key.decode('utf-8')}")

        elif choice == '4':
            private_key = input("Enter your private key: ").encode('utf-8')
            data = input("Enter data to sign: ")
            signature = rsa_sign(private_key, data)
            print(f"Signature: {signature}")

        elif choice == '5':
            public_key = input("Enter the public key: ").encode('utf-8')
            data = input("Enter the data to verify: ")
            signature = input("Enter the signature: ")
            is_valid = rsa_verify(public_key, data, signature)
            print(f"Signature valid: {is_valid}")

        elif choice == '6':
            data = input("Enter data to hash: ")
            hash_value = hash_data(data)
            print(f"Hash: {hash_value}")

        elif choice == '7':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
