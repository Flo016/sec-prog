from ast import literal_eval
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from os import remove
import rsa
import re
import secrets
import socket
from tinyec import registry
from tinyec import ec


# Start Client separately from Server


class Client:
    """Create a client instance which connects to the Server, performs a log in and
       lets you read and send messages."""

    def __init__(self):
        """Create Socket connection, perform login, read/write messages from/to users"""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("127.0.0.1", 600))  # TODO use secure socket
        print("connected")
        keys = self.create_Asymmetric_key()  # [public key, private key]
        self.public_key = keys[0]
        self.private_key = keys[1]
        self.symmetric_key = self.create_symmetric_key()  # [symmetric key, Initial value]
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
                exit(0)

    def user_login(self):
        """if login data exists log in with it. If not create a new account"""

        try:
            with open("client_login_data.txt", 'r', encoding='UTF_8') as user_login:
                self.send_encrypted_authenticated("no")
                line = user_login.read()
                lines = line.split(';')
                # Send Username and Password
                self.send_encrypted_authenticated(lines[1])
                self.send_encrypted_authenticated(lines[0])
                answer = self.receive_encrypted_authenticated(1000)
                print(answer)
                if answer == "Wrong Username or Password, please try again":
                    print(answer)
                    remove("client_login_data.txt")
                    self.client_socket.close()
                    exit(0)
        except OSError:
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
            for i in range(29):
                user_login.write(secrets.choice(possible_symbols))

        # send username and password
        self.send_encrypted_authenticated(username)
        with open("client_login_data.txt", 'r', encoding='UTF_8') as user_login:
            self.send_encrypted_authenticated(str(user_login.read))

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
                username = self.receive_encrypted_authenticated(1024)
                break

        # TODO Privilege management
        with open("client_login_data.txt", 'a') as user_login:
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

        self.send_encrypted_authenticated(user)
        key_material = self.receive_encrypted_authenticated(3000)   # receive recipient Public key
        key_material = literal_eval(key_material)

        public_key = rsa.PublicKey(int(key_material[0]), int(key_material[1]))

        # generate symmetrical key and iv for message
        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        # scalar multiplication of private key and starting point G
        public_number = private_number * curve.g
        key = private_number * public_number
        # turn sha(key.x) to bytes
        key = int(hashlib.sha256(str(key.x).encode()).hexdigest(), 16).to_bytes(32, 'big')
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # generate message,
        # encrypt with symmetric key and iv, encrypt symmetric key and iv with public key

        message = input("What do you want to tell " + user + "?\n"
                        "(messages can only be 1024 characters long)\n"
                        "Message: ")
        while True:
            print(len(message))
            if len(message) > 1024:
                message = input(
                        "Your message was too long, please send a shorter one"
                        ", or write two messages.\n"
                        "Message:")
                continue
            break

        message = cipher.encrypt(pad(message.encode(), AES.block_size))

        # combine message and encrypted keypair and send
        symmetrical_key_pair = str(int.from_bytes(key, 'big')) + \
                               ';' + str(int.from_bytes(iv, 'big'))
        symmetrical_key_pair = rsa.encrypt(symmetrical_key_pair.encode(), public_key)
        message = str(int.from_bytes(message, 'big')) + \
                  ',' + str(int.from_bytes(symmetrical_key_pair, 'big'))
        self.send_encrypted_authenticated(message)

    def receive_message(self):
        """issue receive, then collect all messages until the "end of messages" command"""
        messages = []  # ["success","message1","message2",...,"end of connection]

        self.send_encrypted_authenticated("receive")
        while True:
            # Message Array: [Timestamp, Sender, Message]
            messages.append(self.receive_encrypted_authenticated(3000))
            if messages[len(messages) - 1] == "end_of_messages":
                break
            elif messages[len(messages) - 1] == "No new messages.":
                # if no messages are found, inform user and return from function
                print("No new messages.")
                return True

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
                sorted_after_sender.append(message[1])
                sorted_after_sender[len(sorted_after_sender) - 1].append(message)
            new_sender = True

        # Print messages received by each sender
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
            with open("client_login_data.txt", 'r', encoding='UTF_8') as test:
                test.close()
            try:
                with open("private_key.PEM", 'r', encoding='UTF_8') as key:
                    private_key = rsa.PrivateKey.load_pkcs1(key.read())
                with open("public_key.PEM", 'r', encoding='UTF_8') as key:
                    public_key = rsa.PublicKey.load_pkcs1(key.read())
                return [public_key, private_key]

            except OSError:
                # TODO inform server of changed public keys.
                (public_key, private_key) = rsa.newkeys(2048, accurate=True)
                # exponent = 65537, key_length = 2048 bits
                # private_key object stored in .PEM file
                with open("private_key.pem", 'w', encoding='UTF_8') as key:
                    key.write(private_key.save_pkcs1().decode())
                with open("public_key.pem", 'w', encoding='UTF_8') as key:
                    key.write(public_key.save_pkcs1().decode())
                return [public_key, private_key]

        except OSError:
            (public_key, private_key) = rsa.newkeys(2048, accurate=True)
            # exponent = 65537, key_length = 2048 bits
            # private_key object stored in .PEM file
            with open("private_key.pem", 'w', encoding='UTF_8') as key:
                key.write(private_key.save_pkcs1().decode())
            with open("public_key.pem", 'w', encoding='UTF_8') as key:
                key.write(public_key.save_pkcs1().decode())
            return [public_key, private_key]

    def create_symmetric_key(self):
        """We create a symmetric key bye using the Elliptic Curve Diffie hellman key exchange"""
        self.client_socket.recv(20)

        # load server public key
        with open("Server_public_key.pem", 'r', encoding='UTF_8') as server_public_key:
            server_key = rsa.PublicKey.load_pkcs1(server_public_key.read())

        # send client public key
        self.client_socket.send(str(self.public_key.n).encode())
        self.client_socket.send(str(self.public_key.e).encode())
        print(self.public_key)
        # Check Authenticity
        self.client_socket.recv(10)
        challenge = secrets.token_bytes(245)
        self.client_socket.send(rsa.encrypt(challenge, server_key))
        response = self.client_socket.recv(4000)
        if challenge != response:
            print("Authentication unsuccessful, closing connection - man in the middle attack.")
            self.client_socket.close()
            exit(0)
        print("Authentication successful")

        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)  # create a random multiplier
        # scalar multiplication of private key and starting point G
        public_number = private_number * curve.g
        self.client_socket.send("go".encode())
        print(type(public_number))
        print(public_number.curve)
        # exchange public coordinates (x,y)
        self.client_socket.send(str(public_number.x).encode())
        print("hallo3")
        self.client_socket.recv(10)
        self.client_socket.send(str(public_number.y).encode())
        print("hallo4")
        server_public_number_x = int(self.client_socket.recv(1024).decode())
        print("hallo")
        self.client_socket.send("go".encode())
        server_public_number_y = int(self.client_socket.recv(1024).decode())
        print("hallo2")

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

    def send_encrypted_authenticated(self, message):
        """create and combine message + MAC and encrypt it."""
        message_mac = hashlib.sha256(message.encode()).hexdigest()
        message = message + ';' + message_mac
        print("--- Message send: ---")
        print(message)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.iv)
        message = cipher.encrypt(pad(message.encode(), AES.block_size))
        print(message)
        print(self.iv)
        self.client_socket.send(message)
        self.update_iv()

    def receive_encrypted_authenticated(self, byte_amount):
        """decrypt received message,
           calculate MAC of received message and compare with received MAC"""
        ciphertext = self.client_socket.recv(byte_amount)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.iv)
        message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        message = message.decode().rsplit(';', 1)
        print("--- Message receive ---")
        print(message)
        if message[1] == hashlib.sha256(message[0].encode()).hexdigest():
            self.update_iv()
            return message[0]
        print("Potential Man in the Middle attack detected, shutting down connection")
        self.client_socket.close()
        exit(0)

    def update_iv(self):
        """generate new IV, send it to the Server and update variable self.iv"""
        # this iv is needed to synchronize the iv used to send the first encryption iv.
        self.client_socket.recv(13)
        first_iv = b'thisisthefirstiv'
        actual_iv = secrets.token_bytes(16)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, first_iv)
        message = cipher.encrypt(pad(actual_iv, AES.block_size))
        self.client_socket.send(message)
        self.iv = actual_iv

    def decrypt_sent_message(self, message):
        """reverse the process of writing a message
           turn sent integers back into bytes
           decrypt symmetric key with private key
           decrypt message with symmetric key"""
        parts = message.split(',')
        eventual_message = int(parts[0]).to_bytes((int(parts[0]).bit_length() + 7) // 8, 'big')
        symmetrical_key_pair = int(parts[1]).to_bytes((int(parts[1]).bit_length() + 7) // 8, 'big')
        symmetrical_key_pair = rsa.decrypt(symmetrical_key_pair, self.private_key).decode()
        key_pair = symmetrical_key_pair.split(";")
        symmetrical_key = int(key_pair[0]).to_bytes((int(key_pair[0]).bit_length() + 7) // 8, 'big')
        iv = int(key_pair[1]).to_bytes((int(key_pair[1]).bit_length() + 7) // 8, 'big')

        cipher = AES.new(symmetrical_key, AES.MODE_CBC, iv)
        message = unpad(cipher.decrypt(eventual_message), AES.block_size).decode()

        return message
