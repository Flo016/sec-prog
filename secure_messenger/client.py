"""Creates a Client programme for an encrypted end to end messenger"""
from ast import literal_eval
import base64
import hashlib
from os import remove
import re
import secrets
import socket
from tinyec import registry
from tinyec import ec
from sys import exit as sys_exit
import rsa
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Start Client separately from Server


class Client:
    """Create a client instance which connects to an encrypted end to end messenger
       Server, performs a log in and lets you read and send messages."""

    def __init__(self):
        """Create Socket connection, perform login, read/write messages from/to users"""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("127.0.0.1", 50))
        print("connected")
        keys = self.create_asymmetric_key()  # [public key, private key]
        self.public_key = keys[0]
        self.private_key = keys[1]
        self.symmetric_key = self.create_symmetric_key()
        self.iv = b''
        self.update_iv()
        self.user_login()
        while True:
            command = input(
                "what do you want to do? "
                "[1] Write Message "
                "[2] Read Messages "
                "[3] Close Programme").lower()
            if command in ('1', 'message'):
                self.write_message()
            elif command in ('2', 'receive'):
                self.receive_message()
            elif command in ('3', 'close'):
                self.client_socket.close()
                sys_exit()

    def user_login(self):
        """if login data exists log in with it. If not create a new account"""

        try:
            # Send Username and Password
            with open("client_login_data.txt", 'r', encoding='UTF_8') as user_login:
                self.send_encrypted_authenticated("no")
                self.client_socket.recv(123)   # wait for server ready (go)
                self.send_encrypted_authenticated(user_login.read().split(';')[1])

            self.client_socket.recv(123)   # wait for server ready (go)
            with open("client_login_data.txt", 'r', encoding='UTF_8') as user_login:
                self.send_encrypted_authenticated(user_login.read().split(';')[0])

            answer = self.receive_encrypted_authenticated(1000)
            if answer == "Wrong Username or Password, please try again":
                print(answer)
                remove("client_login_data.txt")
                self.client_socket.close()
                sys_exit()
        except OSError:
            self.create_account()

    def create_account(self):
        """If log in data doesn't exist, create a new account"""
        self.send_encrypted_authenticated("yes")
        self.client_socket.recv(123)
        message = "no login data found, please select a Username.\n" \
                  "Your username can be 3 - 10 characters long and contain \n" \
                  "numbers, ASCII letters and these special characters: . _ -  \n" \
                  "Username: "
        while True:
            username = input(message)
            if re.fullmatch('([A-Za-z0-9]|[._-]){3,10}', username):
                break
            message = "invalid username, please select another one."

        # Create new 30 character password
        print("Creating Password...")
        possible_symbols = \
            "#$%&()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]" \
            "^_`abcdefghijklmnopqrstuvwxyz{|}~"

        # Create file with the first symbol of the password
        with open("client_login_data.txt", 'w', encoding='UTF_8') as user_login:
            user_login.write(secrets.choice(possible_symbols))
        # Append the other 29
        with open("client_login_data.txt", 'a', encoding='UTF_8') as user_login:
            for _ in range(29):
                user_login.write(secrets.choice(possible_symbols))

        # send username and password
        self.send_encrypted_authenticated(username)
        self.client_socket.recv(123)   # wait for server ready (go)
        with open("client_login_data.txt", 'r', encoding='UTF_8') as user_login:
            self.send_encrypted_authenticated(user_login.read())

        while True:
            approved_username = self.receive_encrypted_authenticated(1024)
            print(approved_username)
            if approved_username == "Username unavailable. Please select another Username\n":
                message = approved_username
                while True:
                    username = input(message)
                    if re.fullmatch('([A-Za-z0-9]|[._-]){3,10}', username):
                        break
                    message = "invalid username, please select another one."

                self.send_encrypted_authenticated(username)
            else:
                self.client_socket.send("go".encode())
                username = self.receive_encrypted_authenticated(1024)
                break

        with open("client_login_data.txt", 'a', encoding="UTF_8") as user_login:
            user_login.write(";" + username)

    def write_message(self):
        """issue message command, send recipient, send actual message, """
        self.send_encrypted_authenticated("message")

        user = input("Which user should receive this message? (example: lmao#0550 )")
        while True:
            if not re.fullmatch('([A-Za-z0-9]|[._-]){3,10}#[0-9]{4}', user):
                user = input("Invalid Username syntax. Please provide a possible username.")
                continue
            break

        # generate message,
        message = input("What do you want to tell " + user + "?\n"
                        "(messages can only be 1024 characters long)\n"
                        "Message: ")
        while True:
            print(len(message))
            if len(message) > 1024:
                message = input(
                    "Your message was too long, please send a shorter one, "
                    "or write two messages.\n"
                    "Message:")
                continue
            break

        # receive recipient Public key
        self.send_encrypted_authenticated(user)
        key_material = self.receive_encrypted_authenticated(3000)
        key_material = literal_eval(key_material)
        public_key = rsa.PublicKey(int(key_material[0]), int(key_material[1]))

        # encrypt with symmetric key and an iv, then encrypt key and iv with public key
        # generate symmetrical key and iv for message
        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        # scalar multiplication of private key and starting point G
        public_number = private_number * curve.g
        key = private_number * public_number
        # turn sha(key.x) to bytes

        key = int(hashlib.sha256(str(key.x).encode()).hexdigest(), 16).to_bytes(32, 'big')
        iv = secrets.token_bytes(16)
        pad = str(int.from_bytes(iv, 'big'))

        message = self.encrypt_message(message, key, iv)

        # combine message and encrypted keypair and send
        symmetrical_key_pair = str(int.from_bytes(key, 'big')) + \
                               ';' + str(int.from_bytes(iv, 'big'))

        symmetrical_key_pair = rsa.encrypt(symmetrical_key_pair.encode(), public_key)

        message = str(int.from_bytes(message, 'big')) + \
                  ',' + str(int.from_bytes(symmetrical_key_pair, 'big')) + \
                  ',' + pad

        self.send_encrypted_authenticated(message)

    def receive_message(self):
        """issue receive, then collect all messages until the "end of messages" command"""
        messages = []  # ["success","message1","message2",...,"end of connection]

        self.send_encrypted_authenticated("receive")
        while True:
            # Message Array: [Timestamp, Sender, Message]
            messages.append(self.receive_encrypted_authenticated(5000))
            if messages[len(messages) - 1] == "No new messages.":
                # if no messages are found, inform user and return from function
                print("No new messages.")
                return True
            if messages[len(messages) - 1] == "end_of_messages":
                break

        # Filter first and last message, and convert String arrays to "real" Arrays
        actual_messages = []
        for i in range(0, len(messages) - 1):
            actual_messages.append(literal_eval(messages[i]))

        # Sort messages by senders and print them
        sorted_after_sender = [[actual_messages[0][1]]]  # [[sender1]]
        new_sender = True
        for message in actual_messages:
            for sender in sorted_after_sender:
                for i in range(0, len(sender)):
                    # If sender exists, append message to sender,
                    # else create new sender in sorted_after_sender
                    if message[1] == sender[i]:
                        # Array looks like: [[sender1, message1, message2], [sender2, message1]]
                        sorted_after_sender[i].append(message)
                        new_sender = False
                        break
            if new_sender:
                message_sender = message[1]
                sorted_after_sender.append([message_sender])
                sorted_after_sender[len(sorted_after_sender) - 1].append(message)
            new_sender = True

        # Print messages received by each sender
        for sender in sorted_after_sender:
            print(str(sender[0]) + " wrote: ")
            del sender[0]
            for i in range(len(sender)):  # [[message 1], [message 2], ..., [message i]]
                message = self.decrypt_received_message(sender[i][2])
                print("     " + str(sender[i][0] + " - " + message))  # timestamp - message

            print("")  # to add an empty line to have a better overview

    @staticmethod
    def create_asymmetric_key():
        """Try to read keypair, if impossible create new keypair"""
        try:
            with open("private_key.pem", "r", encoding='UTF_8') as key:
                private_key = rsa.PrivateKey.load_pkcs1(key.read())
            with open("public_key.pem", "r", encoding='UTF_8') as key:
                public_key = rsa.PublicKey.load_pkcs1(key.read())

        except OSError:
            (public_key, private_key) = rsa.newkeys(2048, accurate=True)
            # exponent = 65537, key_length = 2048 bits
            # private_key object stored in .PEM file
            with open("private_key.pem", 'w', encoding='UTF_8') as key:
                key.write(private_key.save_pkcs1().decode())
            with open("public_key.pem", 'w', encoding='UTF_8') as key:
                key.write(public_key.save_pkcs1().decode())
            return [public_key, private_key]

        return [public_key, private_key]

    def create_symmetric_key(self):
        """first we check Partner Authenticity
           then create a symmetric key bye using the Elliptic Curve Diffie hellman key exchange"""

        self.check_authenticity()

        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        # scalar multiplication of private key and starting point G
        public_number = private_number * curve.g
        self.client_socket.send("go".encode())
        # exchange public coordinates (x,y)
        self.client_socket.send(str(public_number.x).encode())
        self.client_socket.recv(10)
        self.client_socket.send(str(public_number.y).encode())
        server_public_number_x = int(self.client_socket.recv(1024).decode())
        self.client_socket.send("go".encode())
        server_public_number_y = int(self.client_socket.recv(1024).decode())

        server_public_number = ec.Point(public_number.curve,
                                        server_public_number_x,
                                        server_public_number_y)

        # calculate symmetric key
        key = private_number * server_public_number
        # hash symmetric key
        # x coordinate is used as symmetric key
        symmetric_key = hashlib.sha256(str(key.x).encode()).hexdigest()
        print("symmetric key is: " + str(symmetric_key))
        symmetric_key = int(symmetric_key, 16).to_bytes(32, 'big')
        return symmetric_key

    def check_authenticity(self):
        """Proves Authenticity of Server via Challenge Response"""
        self.client_socket.recv(20)

        # load server public key
        with open("Server_public_key.pem", 'r', encoding='UTF_8') as server_public_key:
            server_key = rsa.PublicKey.load_pkcs1(server_public_key.read())

        # send client public key
        self.client_socket.send(str(self.public_key.n).encode())
        self.client_socket.send(str(self.public_key.e).encode())
        # Check Authenticity
        self.client_socket.recv(10)
        challenge = secrets.token_bytes(245)
        self.client_socket.send(rsa.encrypt(challenge, server_key))
        response = self.client_socket.recv(4000)
        if challenge != response:
            print("Authentication unsuccessful, closing connection - man in the middle attack.")
            self.client_socket.close()
            sys_exit()
        print("Authentication successful")

    def send_encrypted_authenticated(self, message):
        """Encrypt message, generate next iv and send both"""

        message = self.encrypt_message(message, self.symmetric_key, self.iv)
        self.iv = secrets.token_bytes(16)
        # send next IV and then send message
        self.client_socket.send(self.iv)
        self.client_socket.send(base64.b64encode(message))

    def receive_encrypted_authenticated(self, byte_amount):
        """decrypt received message, update IV and return message"""
        stored_iv = self.client_socket.recv(16)
        ciphertext = self.client_socket.recv(byte_amount)
        ciphertext = base64.b64decode(ciphertext)
        message = self.decrypt_message(ciphertext, self.symmetric_key, self.iv)
        self.iv = stored_iv
        return message

    def update_iv(self):
        """generate new IV, send it to the Server and update variable self.iv
        no padding is needed as the IV is already the correct byte size."""
        # this iv is needed to synchronize the iv used to send the first encryption iv.
        self.client_socket.recv(13)
        first_iv = b'thisisthefirstiv'
        actual_iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(first_iv))
        encryptor = cipher.encryptor()
        message = encryptor.update(actual_iv) + encryptor.finalize()
        self.client_socket.send(message)
        self.iv = actual_iv

    def decrypt_received_message(self, message):
        """reverse the process of writing a message
           turn sent integers back into bytes
           decrypt symmetric key and IV with private key
           decrypt message with symmetric key"""

        def convert_to_bytes(integer_number):
            """round bits up to 8 bytes and turn integer into corresponding bytes"""
            return int(integer_number).to_bytes((int(integer_number).bit_length() + 7) // 8, 'big')

        parts = message.split(',')
        eventual_message = convert_to_bytes(parts[0])
        symmetrical_key_pair = convert_to_bytes(parts[1])
        symmetrical_key_pair = rsa.decrypt(symmetrical_key_pair, self.private_key).decode()
        key_pair = symmetrical_key_pair.split(";")
        symmetrical_key = convert_to_bytes(key_pair[0])
        iv = convert_to_bytes(key_pair[1])
        message = self.decrypt_message(eventual_message, symmetrical_key, iv)
        return message

    @staticmethod
    def encrypt_message(message, key, iv):
        """create and combine message + MAC and encrypt it.
           encryption is done with CBC Padded with the next used IV Value
           -> blocks of incorrect size are of IV and are discarded
              which doesnt matter however as IV is sent separately before."""

        message_mac = hashlib.sha256(message.encode()).hexdigest()
        pad = str(int.from_bytes(iv, 'big'))
        message = (message + ';' + message_mac + ';' + pad).encode()

        # encrypt message
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        message = encryptor.update(message)
        try:
            message += encryptor.finalize()
        except cryptography.exceptions.AlreadyFinalized:
            # This exception occurs on the last block of the encryption.
            # As the last block is supposed to be discarded, the exception does nothing.
            pass
        except ValueError:
            # This exception occurs on the last block of the encryption.
            # As the last block is supposed to be discarded, the exception does nothing.
            pass
        return message

    @staticmethod
    def decrypt_message(ciphertext, key, iv):
        """decrypt message, compare MACs. If MACs are not the same,
         inform user and close connection"""

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        message = decryptor.update(ciphertext)
        try:
            message += decryptor.finalize()
        except ValueError:
            # This exception occurs on the last block of the decryption.
            # As the last block is supposed to be discarded, the exception does nothing.
            pass
        message = message.decode().rsplit(';', 2)
        if message[1] == hashlib.sha256(message[0].encode()).hexdigest():
            return message[0]
        print("Potential Man in the Middle attack detected, shutting down connection")
        return sys_exit
