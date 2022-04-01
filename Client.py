import base64
import pickle
import sys
import time
import rsa
import socket
import OpenSSL
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import Utility
import hashlib
import hmac

# Load certificates, and add Bob's certificate to list of trusted certificates
clientCRT = open('certs/alice.crt')
serverCRT = open('certs/bob.crt')
client_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, clientCRT.read().encode())
server_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, serverCRT.read().encode())
store = OpenSSL.crypto.X509Store()
store.add_cert(server_cert)

clientSocket = socket.socket()

try:
    clientSocket.connect(('127.0.0.1', 8000))

    # Send the encryption scheme Alice and Bob will use, and Alice's certificate
    messageOne = pickle.dumps(['AES', open('certs/alice.crt').read().encode()])
    clientSocket.send(messageOne)

    # Receive Bob's certificate
    messageTwo = clientSocket.recv(8000)
    messageTwoExtracted = pickle.loads(messageTwo)

    # Try to load the certificate that Bob sent to ensure it is valid
    try:
        received_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, messageTwoExtracted[0])
        ctx = OpenSSL.crypto.X509StoreContext(store, received_cert)
    except OpenSSL.crypto.X509StoreContextError:
        print("Invalid certificate, terminating connection")
        clientSocket.close()

    # Verify Alice's certificate against the trusted certificates
    try:
        ctx.verify_certificate()
    except OpenSSL.crypto.X509StoreContextError:
        print("Error Occurred during verification, terminating connection")
        clientSocket.close()

    # Bob is verified
    print("Bob Verified")
    print()

    # Send Alice's encrypted nonce
    alicePubKey = rsa.PublicKey.load_pkcs1_openssl_pem(open('certs/alice_pub.pub', 'rb').read())
    encryptedAliceNonce = rsa.encrypt(str(time.time_ns()).encode(), alicePubKey)
    clientSocket.send(encryptedAliceNonce)

    # Receive Bob's encrypted nonce
    encryptedBobNonce = clientSocket.recv(8000)

    # Create master secret
    masterSecret = Utility.byte_xor(encryptedAliceNonce, encryptedBobNonce)

    print("Generated master secret: " + str(masterSecret))
    print()

    # If the argument is 'true' we alter the hash so the HMAC will not match
    if sys.argv[1] == 'true':
        messageOne = messageOne + b'Client alters the hash'

    # Combine all messages to compute the HMAC
    allMessagesToSend = [messageOne, messageTwo, encryptedAliceNonce, encryptedBobNonce, 'CLIENT']
    allMessagesToVerify = [messageOne, messageTwo, encryptedAliceNonce, encryptedBobNonce, 'SERVER']

    allMessagesToSendCompressed = pickle.dumps(allMessagesToSend)
    allMessagesToVerifyCompressed = pickle.dumps(allMessagesToVerify)

    HMACToSend = hmac.new(masterSecret, allMessagesToSendCompressed, hashlib.sha1)
    HMACToVerify = hmac.new(masterSecret, allMessagesToVerifyCompressed, hashlib.sha1)

    # Send Bob's HMAC
    digestToSend = HMACToSend.digest()
    clientSocket.send(digestToSend)

    # Receive Alice's HMAC
    digestToVerify = clientSocket.recv(8000)
    ourDigest = HMACToVerify.digest()

    # Verify that the HMACs match
    if not hmac.compare_digest(digestToVerify, ourDigest):
        print("Hashes do not match! Exiting connection!")
        sys.exit()
    else:
        print("Hash values match, beginning data transfer")

    print()

    # Generate 4 keys based off the master secret
    # here the master secret becomes the salt for the KDF
    kdf1 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=masterSecret,
        iterations=390000,
    )

    kdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=masterSecret,
        iterations=390000,
    )

    kdf3 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=masterSecret,
        iterations=390000,
    )

    kdf4 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=masterSecret,
        iterations=390000,
    )

    key1 = base64.urlsafe_b64encode(kdf1.derive(b"aliceEncryption"))
    key2 = base64.urlsafe_b64encode(kdf2.derive(b"bobEncryption"))
    key3 = base64.urlsafe_b64encode(kdf3.derive(b"aliceSign"))
    key4 = base64.urlsafe_b64encode(kdf4.derive(b"bobSign"))

    aliceEncrypt = Fernet(key1)
    bobEncrypt = Fernet(key2)
    aliceSign = Fernet(key3)
    bobSign = Fernet(key4)

    print("Keys Generated: ")
    print("Alice Encryption: " + str(key1))
    print("Bob Encryption: " + str(key2))
    print("Alice Integrity Protection: " + str(key3))
    print("Bob Integrity Protection: " + str(key4))
    print()

    # Receive and decrypt the file
    totalString = b''
    while True:
        encryptedFile = clientSocket.recv(4096)
        if not encryptedFile:
            break
        totalString = totalString + encryptedFile

    decryptedFile = bobEncrypt.decrypt(totalString)

    receivedFile = open('receivedMessage.txt', 'w')
    receivedFile.write(decryptedFile.decode())

    print("File received, closing connection!")

    clientSocket.close()

except socket.error:
    print("Error occurred during communication, closing sockets")
    clientSocket.close()
