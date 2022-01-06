"""Creates a Server programme for an encrypted end to end messenger"""
import datetime
import hashlib
from random import randrange
import secrets
import socket
import threading
import time
from tinyec import registry
from tinyec import ec
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Server:
    """create variables for Server"""

    def __init__(self):
        """Create socket object"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Wait for connections and handle them
        self.main_loop()

    def client_connect(self, client_server_socket):  # client_Server_Socket: Socket Object;
        # TODO Symmetric key generation
        """User logs in"""
        # [client_public,  symmetric_key, iv]
        keys = self.create_symmetric_key(client_server_socket)
        # Initialize an object for connection, containing the socket, keys and iv,
        # And also functions to securely send and receive messages
        connection = OnConnection(client_server_socket, keys[0], keys[1], keys[2])

        login_data = self.log_in_request(connection)  # [Username;Login Successful/Unsuccessful]
        current_user = login_data[0]
        if login_data[1]:
            while True:
                print("stuff successful")
                command = connection.receive_encrypted_authenticated(1024)
                if command == "message":
                    self.user_message(connection, current_user)
                elif command == "receive":
                    self.collect_messages(connection, current_user)

        else:  # User password false
            client_server_socket.close()
            return

    def main_loop(self):

        """ Create Server Socket and listen"""
        self.server_socket.bind(("127.0.0.1", 600))  # TODO use secure socket
        print("Server Listening...")
        self.server_socket.listen()

        # Handle one connection per loop cycle
        while True:
            # Wait for connections
            (client_connected, client_address) = self.server_socket.accept()

            # Give Thread to Client and initialize communication
            thread_1 = threading.Thread(target=self.client_connect, args=(client_connected,))
            thread_1.start()
            print("Accepted connection from " + str(client_address))

    def log_in_request(self, connection):
        # TODO MAC for yes and no
        """register an account? - This process is automated with client,
            if client doesnt find local log in data, it creates an account(data_from_client = yes),
            if it does, it performs a login(data_from_client = no)"""
        while True:
            create_an_account = connection.receive_encrypted_authenticated(1024)
            # Request Username and Password  with file name after username
            username_from_client = connection.receive_encrypted_authenticated(2048)

            password_from_client = connection.receive_encrypted_authenticated(1024)

            if create_an_account == "yes":
                login_success_array = self.create_account(
                    connection, username_from_client, password_from_client)
            else:
                try:
                    # file consist of: ("Password; Salt; [Timestamp, Sender, Message]*")
                    print(username_from_client + " trying to log in... ")
                    # compare hashed password from client with password stored in user file
                    with open(f"{username_from_client}.txt", 'r', encoding='UTF_8') as user:
                        password = user.read().split(';')
                        password_from_client = hashlib.sha512(
                            (password_from_client + password[1]).encode()
                        ).hexdigest()
                    if password[0] == password_from_client:
                        print(username_from_client + " log in successful")
                        connection.send_encrypted_authenticated("login success")
                        login_success_array = [username_from_client, True]  # Log in success
                    else:
                        connection.send_encrypted_authenticated(
                            "Wrong Username or Password, please try again")
                        print(username_from_client)
                        # Can only be false, if client data has been manipulated.
                        # therefore we close connection
                        login_success_array = [username_from_client, False]
                except OSError:
                    connection.send_encrypted_authenticated(
                        "Wrong Username or Password, please try again")
                    connection.client_socket.close()
                    login_success_array = [username_from_client, False]

            return login_success_array

    @staticmethod
    def create_account(connection, username_from_client, password_from_client):
        """Give Username a random ID and check if ID already exists,
           if it does, create a new one and repeat"""
        # TODO Check Program privileges

        while True:

            id_array = []
            for i in range(0, 10000):
                id_array.append(f'{i}'.zfill(4))  # create array form 0000-9999
            for id_array_limit in range(9999, -1, -1):
                index = randrange(0, id_array_limit)
                user_id = id_array[index]
                actual_username = username_from_client + "#" + user_id
                # example Username: Lmao#0045
                try:
                    # Check if username+ID already exists,
                    # if yes choose new random ID and delete ID from id_array"""
                    with open(f"{actual_username}.txt", 'r', encoding='UTF_8') as array:
                        array.close()
                    del id_array[:index]
                    continue

                except OSError:
                    # file consist of:
                    # ("Password; Salt; [Public_key, Exponent]; [Timestamp, Sender, Message]*")

                    connection.send_encrypted_authenticated(F"Your Username is: {actual_username}")
                    # Send String with only Username
                    connection.send_encrypted_authenticated(actual_username)

                    # TODO Add pepper (do programme privileges first)
                    # Store data in file, Salt and hash the password, generate Salt
                    possible_symbols = "#$%&()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]" \
                                       "^_`abcdefghijklmnopqrstuvwxyz{|}~"
                    salt = ''
                    for _ in range(10):
                        salt = salt + secrets.choice(possible_symbols)
                    # TODO add VERY SLOW sha algorithm
                    with open(f"{actual_username}.txt", "w", encoding='UTF_8') as login:
                        print(str(password_from_client + salt))
                        login.write(
                            str(hashlib.sha512((password_from_client + salt).encode()).hexdigest())
                            + ';' + salt
                            + ';' + str([connection.client_public_key.n,
                                         connection.client_public_key.e])
                        )

                    return [actual_username, True]

            # If Username exists 10000 times already, use another Username
            connection.send_encrypted_authenticated(
                "Username unavailable. Please select another Username")
            username_from_client = connection.receive_encrypted_authenticated(1024)

    @staticmethod
    def user_message(connection, sender):
        """Send go and wait for the message,
           create a message array with send_time, sender and message"""

        recipient = connection.receive_encrypted_authenticated(1024)
        print(recipient)
        try:
            # check if file exists; file consist of:
            # ("Password;Salt;[Public_key];[Timestamp, Sender, Message]*")
            with open(f"{recipient}.txt", "r", encoding='UTF_8') as user_file:
                # send recipient public key
                connection.send_encrypted_authenticated(user_file.read().split(';')[2])

            message = connection.receive_encrypted_authenticated(4096)
            # take timestamp
            time_stamp = time.time()
            send_time = datetime.datetime.fromtimestamp(time_stamp).strftime('%d-%m-%Y %H:%M')
            # create message array
            message = [send_time, sender, message]
            with open(f"{recipient}.txt", "a", encoding='UTF_8') as user_file:
                user_file.write(";" + str(message))

        except OSError:
            print("Username doesn't exist")
            connection.client_socket.close()

    @staticmethod
    def collect_messages(connection, username):
        """Prepare messages to be sent, store sensitive data and reset the file """
        with open(f"{username}", "r", encoding='UTF_8') as text_data:
            file_data = text_data.read().split(";")
            sensitive_data = []
            for i in range(3):
                sensitive_data.append(file_data[i])
            # send each message one by one
            if len(file_data) > 3:
                for i in range(3, len(file_data)):
                    print(i)
                    connection.send_encrypted_authenticated(file_data[i])
                connection.send_encrypted_authenticated("end_of_messages")
            else:
                connection.send_encrypted_authenticated("No new messages.")
        with open(f"{username}.txt", "w", encoding='UTF_8') as text_data:
            text_data.write(sensitive_data[0])
        with open(f"{username}.txt", "a", encoding='UTF_8') as text_data:
            for i in range(1, len(sensitive_data)):
                text_data.write(";" + sensitive_data[i])
                print(sensitive_data[i])
            return True

    def create_symmetric_key(self, client_server_socket):
        """ first get client Public key and load server Private key
            then authenticate yourself
            then exchange values for Symmetric key
            then receive first iv for further symmetric encryption"""

        client_public = self.check_authenticity(client_server_socket)

        client_server_socket.recv(10)
        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)
        # scalar multiplication of private key and starting point G
        public_number = private_number * curve.g
        # exchange public points (x,y)
        client_public_number_x = int(client_server_socket.recv(1024).decode())
        client_server_socket.send("go".encode())
        client_public_number_y = int(client_server_socket.recv(1024).decode())
        client_server_socket.send(str(public_number.x).encode())
        client_server_socket.recv(10)
        client_server_socket.send(str(public_number.y).encode())
        client_public_number = ec.Point(public_number.curve,
                                        client_public_number_x,
                                        client_public_number_y)
        # calculate symmetric key
        key = private_number * client_public_number
        # hash symmetric key
        symmetric_key = hashlib.sha256(str(key.x).encode()).hexdigest()
        print("Symmetric key is: " + str(symmetric_key))
        symmetric_key = int(symmetric_key, 16).to_bytes(32, 'big')

        # receive first iv
        client_server_socket.send("go".encode())
        # this iv is needed to synchronize the iv used to send the first encryption iv.
        first_iv = b'thisisthefirstiv'
        iv = client_server_socket.recv(2048)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, first_iv)
        iv = unpad(cipher.decrypt(iv), AES.block_size)
        return [client_public, symmetric_key, iv]

    @staticmethod
    def check_authenticity(client_server_socket):
        """Loads Private key to respond to Challenge, sends solved Challenge and
        stores client public key"""

        with open("Private_key.pem", 'r', encoding='UTF_8') as private_key:
            priv_key = rsa.PrivateKey.load_pkcs1(private_key.read())

        client_server_socket.send("public_key?".encode())

        client_public_n = int(client_server_socket.recv(3000).decode())
        client_public_e = int(client_server_socket.recv(1024).decode())
        client_public = rsa.PublicKey(client_public_n, client_public_e)
        # Prove Authenticity
        client_server_socket.send("go".encode())
        challenge = client_server_socket.recv(3500)
        response = rsa.decrypt(challenge, priv_key)
        client_server_socket.send(response)

        return client_public


class OnConnection:
    """Creates an connection object which stores information and provides secure communication"""

    def __init__(self, client_socket, client_public_key, symmetric_key, iv):
        self.client_socket = client_socket
        self.client_public_key = client_public_key
        self.symmetric_key = symmetric_key
        self.iv = iv

    def send_encrypted_authenticated(self, message):
        """create and combine message + MAC and encrypt it."""

        message_mac = hashlib.sha256(message.encode()).hexdigest()
        message = message + ';' + message_mac
        print("--- Message send: ---")
        print(message)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.iv)
        message = cipher.encrypt(pad(message.encode(), AES.block_size))
        self.client_socket.send(message)
        self.update_iv()

    def receive_encrypted_authenticated(self, byte_amount):
        """Receive Message and encrypt it, then check for Authenticity"""
        ciphertext = self.client_socket.recv(byte_amount)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, self.iv)
        self.update_iv()
        message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        message = message.decode().rsplit(';', 1)
        print("--- Message receive ---")
        if message[1] == hashlib.sha256(message[0].encode()).hexdigest():
            return message[0]
        print("Potential Man in the Middle attack detected, shutting down connection")
        self.client_socket.close()
        return None

    def update_iv(self):
        """Update IV after every message that has been sent"""
        # this iv is needed to synchronize the iv used to send the first encryption iv.
        first_iv = b'thisisthefirstiv'
        self.client_socket.send("go".encode())
        actual_iv = self.client_socket.recv(1024)  # iv is always user calculated
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, first_iv)
        self.iv = unpad(cipher.decrypt(actual_iv), AES.block_size)
