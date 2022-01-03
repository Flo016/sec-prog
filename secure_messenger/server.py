import socket
import threading
from random import randrange
import time
import datetime
import secrets
import hashlib
import rsa
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pickle


class Server:
    """create variables for Server"""

    def __init__(self):
        """Create socket object"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        "Wait for connections and handle them"
        self.main_loop()

    def client_connect(self, client_server_socket):  # client_Server_Socket: Socket Object;
        # TODO Symmetric key generation
        """User logs in"""
        keys = self.create_symmetric_key(client_server_socket)  # [client_public,  symmetric_key, IV]
        """Initialize an object for connection, containing the socket, keys and IV, 
           And also functions to securely send and receive messages"""
        print("zazazaza")
        connection = OnConnection(client_server_socket, keys[0], keys[1], keys[2])
        login_data = self.log_in_request(connection)   # [Username;Login Successful/Unsuccessful]
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

        """ Handle one connection per loop cycle"""
        while True:

            """ Wait for connections """
            (client_connected, client_Address) = self.server_socket.accept()

            """ Create Array with User Information(IP & Port) """
            array = []
            for item in client_connected.getpeername():
                array.append(item)

            """ Give Thread to Client and initialize communication"""
            thread_1 = threading.Thread(target=self.client_connect, args=(client_connected,))
            thread_1.start()
            print("Accepted connection from " + str(array[0]) + ":" + str(array[1]))

    def log_in_request(self, connection):
        # TODO MAC for yes and no
        """register an account? - This process is automated with client, if client doesnt find local log in data
            it creates an account(data_from_client = yes), if it does, it performs a login(data_from_client = no)"""
        while True:
            create_account = connection.receive_encrypted_authenticated(1024)

            """Request Username and Password  with file name after username"""
            username_from_client = connection.receive_encrypted_authenticated(2048)

            password_from_client = connection.receive_encrypted_authenticated(1024)

            if create_account == "yes":
                return self.create_account(connection, username_from_client, password_from_client)
            else:
                try:
                    # file consist of: ("Password; Salt; [Timestamp, Sender, Message]*")
                    print(username_from_client + " trying to log in... ")
                    """ compare hashed password from client with password stored in user file """
                    with open('{}.txt'.format(username_from_client), 'r') as user_file:
                        print("works")
                        password = user_file.read().split(';')
                        print("works")
                        print(password[1])
                        password_from_client = hashlib.sha512((password_from_client + password[1]).encode()).hexdigest()
                    if password[0] == password_from_client:
                        print(username_from_client + " log in successful")
                        connection.send_encrypted_authenticated("login success")
                        return [username_from_client, True]  # Log in success
                    else:
                        connection.send_encrypted_authenticated("ERROR: Wrong Password, please try again")
                        """Can only be false, if client data has been manipulated, therefore we close connection"""
                        return [username_from_client, False]

                except Exception:
                    connection.send_encrypted_authenticated("no login data found, please create a new account")

    @staticmethod
    def create_account(connection, username_from_client, password_from_client):

        # TODO Check Program privileges

        while True:
            """Give Username a random ID and check if ID already exists, if it does, create a new one and repeat"""
            id_array = []
            for i in range(0, 10000):
                id_array.append('{:d}'.format(i).zfill(4))  # create array form 0000-9999
            for id_array_limit in range(9999, -1, -1):
                index = randrange(0, id_array_limit)
                userID = id_array[index]
                actualUsername = username_from_client + "#" + userID  # example Username: Lmao#0045
                try:
                    """Check if username+ID already exists, if yes choose new random ID and delete ID from idArray"""
                    open('{}.txt'.format(actualUsername), 'r')
                    del id_array[:index]
                    continue

                except Exception:
                    """ Create new file if username+ID doesn't exist 
                    check if file exists; file consist of: ("Password; Salt; [Public_key, Exponent]; [Timestamp, Sender, Message]*")
                    """
                    connection.send_encrypted_authenticated("Your Username is: {}".format(actualUsername))
                    connection.send_encrypted_authenticated(actualUsername)  # Send String with only Username

                    # TODO Add pepper (do Programm Priviliges first)
                    """Store data in file, Salt and hash the password"""
                    """generate Salt"""
                    possible_symbols = "#$%&()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                    salt = ''
                    for i in range(10):
                        salt = salt + secrets.choice(possible_symbols)
                    password = password_from_client + salt
                    # TODO add VERY SLOW sha algorithm
                    password = hashlib.sha512(password.encode())  # need byte object: therefore we encode the String
                    login_data = open('{}.txt'.format(actualUsername), "w")
                    login_data.write(str(password.hexdigest()) + ";" + salt + ';' + str([connection.client_public_key.n,
                                                                                         connection.client_public_key.e]))
                    login_data.close()
                    return [actualUsername, True]

            """If Username exists 10000 times already, use another Username"""
            connection.send_encrypted_authenticated("Username unavailable. Please select another Username")
            username_from_client = connection.receive_encrypted_authenticated(1024)

    @staticmethod
    def user_message(connection, sender):
        """Send go and wait for the message, create a message array with send_time, sender and message"""

        recipient = connection.receive_encrypted_authenticated(1024)
        print(recipient)
        try:
            # check if file exists; file consist of: ("Password;Salt;[Public_key];[Timestamp, Sender, Message]*")
            user_file = open("{name}.txt".format(name=recipient), "r")
            """send recipient public key"""
            connection.send_encrypted_authenticated(user_file.read().split(';')[2])
            user_file.close()
            message = connection.receive_encrypted_authenticated(4096)
            # take timestamp
            time_stamp = time.time()
            send_time = datetime.datetime.fromtimestamp(time_stamp).strftime('%d-%m-%Y %H:%M')
            # create message array
            message = [send_time, sender, message]
            user_file = open("{name}.txt".format(name=recipient), "a")
            user_file.write(";" + str(message))
            user_file.close()

        except Exception:
            print("Username doesn't exist")  # TODO delete this statement
            i = 7 / 0
            # How do you pretend to send "correct" public keys without giving away that users dont exist?

    @staticmethod
    def collect_messages(connection, username):
        """Prepare messages to be sent, store sensitive data and reset the file """
        with open("{name}.txt".format(name=username), "r") as text_data:
            file_data = text_data.read().split(";")
            sensitive_data = []
            for i in range(3):
                sensitive_data.append(file_data[i])
            """send each message one by one"""
            if len(file_data) > 3:
                for i in range(3, len(file_data)):
                    print(i)
                    connection.send_encrypted_authenticated(file_data[i])
                connection.send_encrypted_authenticated("end_of_messages")
            else:
                connection.send_encrypted_authenticated("Keine neuen Nachrichten.")
                return True
        with open("{name}.txt".format(name=username), "w") as text_data:
            text_data.write(sensitive_data[0])
        with open("{name}.txt".format(name=username), "a") as text_data:
            for i in range(1, len(sensitive_data)):
                text_data.write(";" + sensitive_data[i])
                print(sensitive_data[i])
            return True

    @staticmethod
    def create_symmetric_key(client_server_socket):
        """ first get client Public key and load server Private key
            then authenticate yourself
            then exchange values for Symmetric key
            then receive first IV for further symmetric encryption"""

        with open("Private_key.pem", 'r') as private_key:
            priv_key = rsa.PrivateKey.load_pkcs1(private_key.read())

        client_server_socket.send("public_key?".encode())
        client_public = pickle.loads(client_server_socket.recv(3000))

        """Prove Authenticity"""
        client_server_socket.send("go".encode())
        challenge = client_server_socket.recv(3500)
        response = rsa.encrypt(rsa.decrypt(challenge, priv_key), client_public)
        client_server_socket.send(response)
        client_server_socket.recv(10)

        curve = registry.get_curve('brainpoolP256r1')
        private_number = secrets.randbelow(curve.field.n)
        public_number = private_number * curve.g  # scalar multiplication of private key and starting point G

        """exchange public points (x,y)"""
        client_public_number = pickle.loads(client_server_socket.recv(2000))
        client_server_socket.send(pickle.dumps(public_number))

        """calculate symmetric key"""
        key = private_number * client_public_number
        """hash symmetric key"""
        symmetric_key = hashlib.sha256(str(key.x).encode()).hexdigest()
        print("Symmetric key is: " + str(symmetric_key))
        symmetric_key = int(symmetric_key, 16).to_bytes(32, 'big')

        """receive first IV"""
        client_server_socket.send("go".encode())
        first_IV = b'thisisthefirstIV'  # this IV is needed to synchronize the IV used to send the first encryption IV.
        IV = client_server_socket.recv(2048)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, first_IV)
        IV = unpad(cipher.decrypt(IV), AES.block_size)
        return [client_public, symmetric_key, IV]


class OnConnection:
    def __init__(self, client_socket, client_public_key, symmetric_key, IV):
        self.client_socket = client_socket
        self.client_public_key = client_public_key
        self.symmetric_key = symmetric_key
        self.IV = IV

    def send_encrypted_authenticated(self, message):
        """create and combine message + MAC and encrpyt it."""
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
        self.update_IV()
        message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        message = message.decode().rsplit(';', 1)
        print("--- Message receive ---")
        print(message)
        if message[1] == hashlib.sha256(message[0].encode()).hexdigest():
            return message[0]
        print("Potential Man in the Middle attack detected, shutting down connection")
        i = 7 / 0

    def update_IV(self):

        first_IV = b'thisisthefirstIV'  # this IV is needed to synchronize the IV used to send the first encryption IV.
        self.client_socket.send("go".encode())
        actual_IV = self.client_socket.recv(1024)   # IV is always user calculated
        print(actual_IV)
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, first_IV)
        self.IV = unpad(cipher.decrypt(actual_IV), AES.block_size)
        print("successfully updated")
