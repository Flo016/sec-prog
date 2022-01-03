import re
import socket
import rsa
import secrets  # TODO maybe explain why this library?
from ast import literal_eval
from tinyec import registry
import hashlib
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import remove

"""Start Client separately from Server"""


class Client:

    def __init__(self):
        """Create Socket connection, perform login, read/write messages from/to users"""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("127.0.0.1", 600))  # TODO use secure socket
        print("connected")
        keys = self.create_Asymmetric_key()  # [public key, private key]
        self.public_key = keys[0]
        self.private_key = keys[1]
        self.symmetric_key = self.create_symmetric_key()  # [symmentric key, Initial value]
        self.IV = b''
        self.update_IV()
        self.user_login()
        while True:
            command = input("what do you want to do? [1] Write Message [2] Read Messages [3] Close Programm").lower()
            if command in ('1', ):
                self.write_message()
            elif command == "2" or command == "read":
                self.receive_message()
            elif command == "3" or command == "close":
                i = 7 / 0

    def user_login(self):
        """Connect to Server Socket"""

        try:
            """If log in data exists, try to log in with it"""
            with open("client_login_data.txt", 'r') as user_login:
                self.send_encrypted_authenticated("no")
                line = user_login.read()
                lines = line.split(';')
                self.send_encrypted_authenticated(lines[0])  # send Username
                self.send_encrypted_authenticated(lines[1])  # send password
                """wait for confirmation"""
                answer = self.receive_encrypted_authenticated(200)
                print(answer)
                if answer == "no login data found, please create a new account":
                    remove("client_login_data.txt")
                    i = 7 / 0
        except Exception:
            self.create_account()

    def create_account(self):
        """If log in data doesn't exist, create a new account"""
        self.send_encrypted_authenticated("yes")
        message = "no login data found, please select a Username.\n" \
                  "Your username can be 3 - 10 characters long and contain \n" \
                  "numbers, ASCII letters and these special characters: . _ -  \n" \
                  "Username: "
        while True:
            username = input(message)
            if re.fullmatch('([A-Za-z0-9]|[._-]){3,10}', username):
                break
            message = "invalid username, please select another one."

        print("Creating Password...")
        """Create a new Password"""
        possible_symbols = "#$%&()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        password = ''
        for i in range(30):
            password = password + secrets.choice(possible_symbols)

        self.send_encrypted_authenticated(username)  # send Username
        self.send_encrypted_authenticated(password)  # send Password

        while True:
            approved_username = self.receive_encrypted_authenticated(1024)
            print(approved_username)
            if approved_username == "Username unavailable. Please select another Username":

                while True:
                    username = input(message)
                    if re.fullmatch('([A-Za-z0-9]|[._-]){3,10}', username):
                        break
                    message = "invalid username, please select another one."

                self.send_encrypted_authenticated(username)
            else:
                username = self.receive_encrypted_authenticated(1024)
                break

        # TODO Privilige management
        with open("client_login_data.txt", 'w') as user_login:
            user_login.write(username + ";" + password)

    def write_message(self):
        """issue message command, send receipient, send actuall message, """
        self.send_encrypted_authenticated("message")

        user = input("Which user should receive this message? (example: lmao#0550 )")
        while True:
            if not re.fullmatch('([A-Za-z0-9]|[._-]){3,10}#[0-9]{4}', user):
                user = input("Invalid Username syntax. Please provide a possible username.")
                continue
            break

        self.send_encrypted_authenticated(user)
        key_material = self.receive_encrypted_authenticated(3000)   # receive recipient Public key
        key_material = literal_eval(key_material)

        public_key = rsa.PublicKey(int(key_material[0]), int(key_material[1]))

        """generate symmetrical key and IV for message"""
        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        public_number = private_number * curve.g  # scalar multiplication of private key and starting point G
        key = private_number * public_number
        key = int(hashlib.sha256(str(key.x).encode()).hexdigest(), 16).to_bytes(32, 'big')   # turn sha(key.x) to bytes
        IV = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, IV)

        """generate message, encrypt with symmetric key and IV, encrypt symmetric key and IV with public key"""

        message = input("What do you want to tell " + user + "? (messages can only be 1024 characters long)\n"
                        "Message: ")
        while True:
            print(len(message))
            if len(message) > 1024:
                message = input("Your message was too long, please send a shorter one, or write two messages.\n"
                                "Message:")
                continue
            break

        message = cipher.encrypt(pad(message.encode(), AES.block_size))

        """combine message and encrypted keypair and send"""
        symmetrical_key_pair = str(int.from_bytes(key, 'big')) + ';' + str(int.from_bytes(IV, 'big'))
        symmetrical_key_pair = rsa.encrypt(symmetrical_key_pair.encode(), public_key)
        message = str(int.from_bytes(message, 'big')) + ',' + str(int.from_bytes(symmetrical_key_pair, 'big'))
        self.send_encrypted_authenticated(message)

    def receive_message(self):
        """issue receive, then collect all messages until the "end of messages" command"""
        messages = []  # ["success","message1","message2",...,"end of connection]

        self.send_encrypted_authenticated("receive")
        while True:
            messages.append(self.receive_encrypted_authenticated(3000))  # Message Array: [Timestamp, Sender, Message]
            if messages[len(messages) - 1] == "end_of_messages":
                break
            elif messages[len(messages) - 1] == "Keine neuen Nachrichten.":
                # if no messages are found, inform user and return from function
                print("Keine neuen Nachrichten.")
                return True

        """Filter first and last message, and convert String arrays to "real" Arrays"""
        print(messages)
        actual_messages = []
        for i in range(0, len(messages) - 1):
            actual_messages.append(literal_eval(messages[i]))
        print("Actually: ")
        print(actual_messages)

        """Sort messages by senders and print them"""
        sorted_after_sender = [[actual_messages[0][1]]]  # [[sender1]]
        new_sender = True
        for message in actual_messages:
            for sender in sorted_after_sender:
                for i in range(0, len(sender)):
                    """If sender exists, append message to sender, else create new sender in sorted_after_sender"""
                    if message[1] == sender[i]:
                        sorted_after_sender[i].append(message)  # [[sender1, message1, message2],[sender2, message1]]
                        new_sender = False
                        break
            if new_sender:
                temp_sender_array = [message[1]]
                sorted_after_sender.append(temp_sender_array)
                sorted_after_sender[len(sorted_after_sender) - 1].append(message)
            new_sender = True

        """Print messages received by each sender"""
        for sender in sorted_after_sender:
            print(str(sender[0]) + " wrote: ")
            del sender[0]
            for i in range(len(sender)):  # [[message 1], [message 2], ..., [message i]]
                print(sender[i][2])
                message = self.decrypt_sent_message(sender[i][2])
                print("     " + str(sender[i][0] + " - " + message))  # timestamp - message

            print("\n")

    @staticmethod
    def create_Asymmetric_key():
        """Try to read keypair, if impossible create new keypair"""
        try:
            test = open("client_login_data.txt", 'r')
            test.close()
            try:
                with open("private_key.PEM", 'r') as key:
                    private_key_from_document = rsa.PrivateKey.load_pkcs1(key.read())
                with open("public_key.PEM", 'r') as key:
                    public_key_from_document = rsa.PublicKey.load_pkcs1(key.read())
                return [public_key_from_document, private_key_from_document]
            except Exception:

                (public_key, private_key) = rsa.newkeys(2048, accurate=True)  # exponent = 65537, key_length = 2048 bits
                with open("private_key.pem", 'w') as key:  # private_key object stored in .PEM file
                    key.write(private_key.save_pkcs1().decode())
                with open("public_key.pem", 'w') as key:
                    key.write(public_key.save_pkcs1().decode())
                return [public_key, private_key]

        except Exception:
            (public_key, private_key) = rsa.newkeys(2048, accurate=True)  # exponent = 65537, key_length = 2048 bits
            with open("private_key.pem", 'w') as key:  # private_key object stored in .PEM file
                key.write(private_key.save_pkcs1().decode())
            with open("public_key.pem", 'w') as key:
                key.write(public_key.save_pkcs1().decode())
            return [public_key, private_key]

    def create_symmetric_key(self):
        """We create a symmetric key bye using the Elliptic Curve Diffie hellman key exchange"""
        self.client_socket.recv(20)

        with open("Server_public_key.pem", 'r') as server_public_key:
            server_key = rsa.PublicKey.load_pkcs1(server_public_key.read())

        self.client_socket.send(pickle.dumps(self.public_key))

        """Check Authenticity"""
        self.client_socket.recv(10)
        challenge = secrets.token_bytes(245)
        self.client_socket.send(rsa.encrypt(challenge, server_key))
        response = rsa.decrypt(self.client_socket.recv(3500), self.private_key)
        if challenge != response:
            print("Authentification unsuccessful, closing connection.")
            i = 7 / 0
        print("Authentification successful")

        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        public_number = private_number * curve.g  # scalar multiplication of private key and starting point G
        self.client_socket.send("go".encode())

        """exchange public coordinates (x,y)"""
        self.client_socket.send(pickle.dumps(public_number))
        server_public_number = pickle.loads(self.client_socket.recv(1024))

        """calculate symmetric key"""
        key = private_number * server_public_number
        """hash symmetric key"""
        symmetric_key = hashlib.sha256(str(key.x).encode()).hexdigest()  # x coordinate is used as symmetric key
        print("Symmetric key is: " + str(symmetric_key))
        symmetric_key = int(symmetric_key, 16).to_bytes(32, 'big')
        return symmetric_key

    def send_encrypted_authenticated(self, message):
        """create and combine message + MAC and encrpyt it."""
        message = message
        messageMAC = hashlib.sha256(message.encode()).hexdigest()
        message = message + ';' + messageMAC
        print("--- Message send: ---")
        print(message)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.IV)
        message = cipher.encrypt(pad(message.encode(), AES.block_size))
        self.client_socket.send(message)
        self.update_IV()

    def receive_encrypted_authenticated(self, byte_amount):
        ciphertext = self.client_socket.recv(byte_amount)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.IV)
        message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        message = message.decode().rsplit(';', 1)
        print("--- Message receive ---")
        print(message)
        if message[1] == hashlib.sha256(message[0].encode()).hexdigest():
            self.update_IV()
            return message[0]
        print("Potential Man in the Middle attack detected, shutting down connection")
        i = 7 / 0
        return

    def update_IV(self):
        print(self.client_socket.recv(1024))
        print("hallo")
        first_IV = b'thisisthefirstIV'  # this IV is needed to synchronize the IV used to send the first encryption IV.
        actual_IV = secrets.token_bytes(16)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, first_IV)
        message = cipher.encrypt(pad(actual_IV, AES.block_size))
        print(message)
        self.client_socket.send(message)
        print("stuff sent")
        self.IV = actual_IV
        print(self.IV)

    def decrypt_sent_message(self, message):
        """reverse the process of writing a message"""
        parts = message.split(',')
        eventual_message = int(parts[0]).to_bytes((int(parts[0]).bit_length() + 7) // 8, 'big')
        symmetrical_key_pair = int(parts[1]).to_bytes((int(parts[1]).bit_length() + 7) // 8, 'big')
        symmetrical_key_pair = rsa.decrypt(symmetrical_key_pair, self.private_key).decode()
        key_pair = symmetrical_key_pair.split(";")
        symmetrical_key = int(key_pair[0]).to_bytes((int(key_pair[0]).bit_length() + 7) // 8, 'big')
        IV = int(key_pair[1]).to_bytes((int(key_pair[1]).bit_length() + 7) // 8, 'big')

        cipher = AES.new(symmetrical_key, AES.MODE_CBC, IV)
        message = unpad(cipher.decrypt(eventual_message), AES.block_size).decode()

        return message
