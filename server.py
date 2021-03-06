import socket
import threading
import time
import datetime


class Server:
    """create variables for Server"""

    def __init__(self):
        """Create socket object"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        "Wait for connections and handle them"
        self.main_loop()

    # client_Server_Socket: Socket Object; array: [Client_IP; Client_Port]
    def client_connect(self,client_server_socket):
        """User logs in"""
        login_data = self.log_in_request(client_server_socket)  # [Username;Login Successful/Unsuccessful]
        current_user = login_data[0]
        print(current_user)
        if login_data[1]:
            while True:
                print("stuff successful")
                command = client_server_socket.recv(1024).decode()
                if command == "message":
                    self.user_message(client_server_socket, current_user)
                elif command == "receive":
                    self.collect_messages(client_server_socket, current_user)

        else:  # User password false
            client_server_socket.close()
            return

    def main_loop(self):

        """ Create Server Socket and listen"""
        self.server_socket.bind(("127.0.0.1", 600))
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

    def log_in_request(self, client_server_socket):
        """register an account? - This process is automated with client, if client doesnt find local log in data
            it creates an account(data_from_client = yes), if it does, it performs a login(data_from_client = no)"""

        create_account = client_server_socket.recv(1024).decode()

        """Request Username and Password  with file name after username"""
        client_server_socket.send("Username?".encode())
        username_from_client = client_server_socket.recv(1024).decode()

        client_server_socket.send("Password?".encode())
        password_from_client = client_server_socket.recv(1024).decode()

        while True:
            if create_account == "yes":
                return self.create_account(client_server_socket, username_from_client, password_from_client)
            else:
                try:
                    # file consist of: ("Password; Salt; [Timestamp, Sender, Message]*")
                    login_data = open('{}.txt'.format(username_from_client), 'r')
                    password = login_data.read().split(';')[0]  # read 0th element contained in the file

                    if password == password_from_client:
                        client_server_socket.send("success".encode())
                        return [username_from_client, True]  # Log in success
                    else:

                        client_server_socket.send("ERROR: Wrong Password, please try again".encode())
                        """Can only be false, if client data has been manipulated, therefore we close connection"""
                        return [username_from_client, False]
                except Exception:
                    client_server_socket.send("no login data found, creating new account".encode())
                    create_account = "yes"

    @staticmethod
    def create_account(client_server_socket, username_from_client, password_from_client):
        while True:
            # client_server_socket.send("Public key?")
            # public_key_from_client = client_server_socket.recv(1024).decode()

            actual_username = username_from_client
            try:
                open('{}.txt'.format(actual_username), 'r')

            except Exception:
                """ Create new file if username+ID doesn't exist 
                file consist of: ("Password, Salt, (Message, Sender)*") """
                client_server_socket.send(("Your Username is: {}".format(actual_username)).encode())
                client_server_socket.recv(1024)
                client_server_socket.send(actual_username.encode())
                login_data = open('{}.txt'.format(actual_username), "w")
                login_data.write(password_from_client)
                login_data.close()
                return [actual_username, True]

            """If Username exists 10000 times already, use another Username"""
            client_server_socket.send(("Username unavailable. Please select another Username".encode()))
            username_from_client = client_server_socket.recv(1024).decode()

    @staticmethod
    def user_message(client_server_socket, sender):
        """Send go and wait for the message, create a message array with send_time, sender and message"""
        client_server_socket.send("go".encode())
        recipient = client_server_socket.recv(1024).decode()
        try:
            # check if file exists; file consist of: ("Password; Salt; [Timestamp, Sender, Message]*")
            user_file = open("{name}.txt".format(name=recipient), "a")
            client_server_socket.send("send message".encode())
            message = client_server_socket.recv(1024).decode()
            # take timestamp
            time_stamp = time.time()
            send_time = datetime.datetime.fromtimestamp(time_stamp).strftime('%d-%m-%Y %H:%M')
            # create message array
            message = [send_time, sender, message]
            user_file.write(";" + str(message))

            user_file.close()
            client_server_socket.send("end message".encode())
        except Exception:
            print("Username doesn't exist")

    @staticmethod
    def collect_messages(client_server_socket, username):
        """Prepare messages to be sent, store sensitive data and reset the file """
        with open("{name}.txt".format(name=username), "r") as text_data:
            file_data = text_data.read().split(";")
            sensitive_data = file_data[0]
            """send each message one by one"""
            if len(file_data) > 1:
                for i in range(1, len(file_data)):
                    client_server_socket.send(file_data[i].encode())
                    client_server_socket.recv(1024)
            else:
                client_server_socket.send("Keine neuen Nachrichten.".encode())
                return True
        with open("{name}.txt".format(name=username), "w") as text_data:
            text_data.write(sensitive_data)
            client_server_socket.send("end_of_messages".encode())
            return True
