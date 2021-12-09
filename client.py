import socket
# import rsa
import secrets  # TODO maybe explain why this library?

"""Start Client separately from Server"""


class Client:

    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.user_login()
        command = input("hallo")
        self.write_message()


    def user_login(self):
        """Connect to Server Socket"""
        self.client_socket.connect(("127.0.0.1", 600))  # TODO use secure socket

        print("connected")
        try:
            """If log in data exists, try to log in with it"""
            with open("client_login_data.txt", 'r') as user_login:
                self.client_socket.send("no".encode())
                line = user_login.read()
                lines = line.split(',')
                self.client_socket.recv(1024).decode()
                self.client_socket.send(lines[0].encode())  # send username
                self.client_socket.recv(1024).decode()  # wait for "send password"
                self.client_socket.send(lines[1].encode())  # send password
                """wait for confirmation"""

        except:
            print("exception")
            """If log in data doesn't exist, create a new account"""
            self.client_socket.send("yes".encode())
            username = input("No login data found - Please select a Username:")

            with open("client_login_data.txt", 'w') as user_login:

                """Create a new Password"""
                possible_symbols = "#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                password = ''
                for i in range(30):
                    password = password + secrets.choice(possible_symbols)
                user_login.write(username +"," + password)

                """ public_key, private_key = rsa.newkeys(512) #TODO Secure Private key in safe file
                user_login.write(public_key+"\n")
                user_login.write(private_key+"\n")"""

            self.client_socket.send(username.encode())  # send Username
            self.client_socket.recv(1024)  # wait for "send password"
            self.client_socket.send(password.encode())  # send Password TODO send encrypted password

            pass

    def write_message(self):
        self.client_socket.send("message".encode())
        user = input("Which user should receive this message?\n")
        message = input("What do you want to tell " + user + "?")
        self.client_socket.send(user.encode()) # sends message receiver
        self.client_socket.recv(1024).decode() # waits for message receiver handling to end until next command is issued
        self.client_socket.send(message.encode()) # send message
        self.client_socket.recv(1024).decode() # wait for message handling to end, until next command can be issued







    """
    def encrypt_message(self, message):
         user_message = input("Please write your message :)  :")
         print("original string: ", user_message)
         user_message = rsa.encrypt(user_message.encode(), public_key)  # TODO encrypt data
         print("encrypt string: ", user_message)
         user_message = rsa.decrypt(user_message, private_key).decode()
         print("decrypted string: ", user_message)
    """