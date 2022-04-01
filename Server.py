import base64
import pickle
import sys
import time
import rsa
import socket
import OpenSSL
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import Utility
import hashlib
import hmac
from cryptography.fernet import Fernet

# Load certificates, and add Alice's certificate to list of trusted certificates
clientCRT = open('certs/alice.crt')
serverCRT = open('certs/bob.crt')
client_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, clientCRT.read().encode())
server_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, serverCRT.read().encode())
store = OpenSSL.crypto.X509Store()
store.add_cert(client_cert)

serverSocket = socket.socket()
serverSocket.bind(('', 8000))
serverSocket.listen(5)

try:
    c, address = serverSocket.accept()

    # Receive certificate and chosen cipher from Alice
    messageOne = c.recv(10000)
    messageOneExtracted = pickle.loads(messageOne)

    print("Chosen Cipher: " + messageOneExtracted[0])
    print()

    # Try to load the certificate that Alice sent to ensure it is valid
    try:
        received_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, messageOneExtracted[1])
        ctx = OpenSSL.crypto.X509StoreContext(store, received_cert)
    except OpenSSL.crypto.X509StoreContextError:
        print("Invalid certificate, terminating connection")
        serverSocket.close()

    # Verify Alice's certificate against the trusted certificates
    try:
        ctx.verify_certificate()
    except OpenSSL.crypto.X509StoreContextError:
        print("Error Occurred during verification, terminating connection")
        serverSocket.close()

    # Alice is verified
    print("Alice verified")
    print()

    # Send Bob's certificate to Alice
    messageTwo = pickle.dumps([open('certs/bob.crt').read().encode()])
    c.send(messageTwo)

    # Receive Alice's encrypted nonce
    encryptedAliceNonce = c.recv(8000)

    # Send Bob's encrypted nonce
    bobPubKey = rsa.PublicKey.load_pkcs1_openssl_pem(open('certs/bob_pub.pub', 'rb').read())
    encryptedBobNonce = rsa.encrypt(str(time.time_ns()).encode(), bobPubKey)
    c.send(encryptedBobNonce)

    # Create master secret
    masterSecret = Utility.byte_xor(encryptedAliceNonce, encryptedBobNonce)

    print("Generated master secret: " + str(masterSecret))
    print()

    # If the argument is 'true' we alter the hash so the HMAC will not match
    if sys.argv[1] == 'true':
        messageOne = messageOne + b'Server alters the hash'

    # Combine all messages to compute the HMAC
    allMessagesToSend = [messageOne, messageTwo, encryptedAliceNonce, encryptedBobNonce, 'SERVER']
    allMessagesToVerify = [messageOne, messageTwo, encryptedAliceNonce, encryptedBobNonce, 'CLIENT']

    allMessagesToSendCompressed = pickle.dumps(allMessagesToSend)
    allMessagesToVerifyCompressed = pickle.dumps(allMessagesToVerify)

    HMACToSend = hmac.new(masterSecret, allMessagesToSendCompressed, hashlib.sha1)
    HMACToVerify = hmac.new(masterSecret, allMessagesToVerifyCompressed, hashlib.sha1)

    # Receive Alice's HMAC
    digestToVerify = c.recv(8000)
    ourDigest = HMACToVerify.digest()

    # Send Bob's HMAC
    digestToSend = HMACToSend.digest()
    c.send(digestToSend)

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

    # Begin transfer of the file
    transferFile = open('serverMessage.txt').read().encode()
    encryptedFile = bobEncrypt.encrypt(transferFile)
    c.sendall(encryptedFile)
    print("File sent, closing connection!")
    c.close()

except socket.error:
    print("Error occurred during communication, closing sockets")
    serverSocket.close()
