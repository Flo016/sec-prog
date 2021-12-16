import socket
# import rsa
import secrets  # TODO maybe explain why this library?
from ast import literal_eval

"""Start Client separately from Server"""


class Client:

    def __init__(self):
        """Create Socket connection, perform login, read/write messages from/to users"""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.user_login()
        while True:
            command = input("what do you want to do? [1] Write Message [2] Read Messages [3] Close Programm").lower()
            if command == "1" or command == "message":
                self.write_message()
            elif command == "2" or command == "read":
                self.receive_message()


    def user_login(self):
        """Connect to Server Socket"""
        self.client_socket.connect(("127.0.0.1", 600))  # TODO use secure socket

        print("connected")
        try:
            """If log in data exists, try to log in with it"""
            with open("client_login_data.txt", 'r') as user_login:
                self.client_socket.send("no".encode())
                self.client_socket.recv(1024)  # each empty recv is a "wait for server"
                line = user_login.read()
                lines = line.split(';')
                self.client_socket.send(lines[0].encode())  # send username
                self.client_socket.recv(1024)
                self.client_socket.send(lines[1].encode())  # send password
                """wait for confirmation"""

        except:
            """If log in data doesn't exist, create a new account"""
            self.client_socket.send("yes".encode())
            self.client_socket.recv(1024)
            username = input("No login data found - Please select a Username:")

            """Create a new Password"""
            possible_symbols = "#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            password = ''
            for i in range(30):
                password = password + secrets.choice(possible_symbols)

            self.client_socket.send(username.encode())  # send Username
            self.client_socket.recv(1024)
            self.client_socket.send(password.encode())  # send Password TODO send encrypted password
            while True:
                approved_username = self.client_socket.recv(1024).decode()
                print(approved_username)
                if approved_username == "Username unavailable. Please select another Username":
                    username = input("")
                    self.client_socket.send(username.encode())
                else:
                    self.client_socket.send("hey".encode())
                    username = self.client_socket.recv(1024).decode()
                    break


            with open("client_login_data.txt", 'w') as user_login:

                user_login.write(username + ";" + password)

                """ public_key, private_key = rsa.newkeys(512) #TODO Secure Private key in safe file
                user_login.write(public_key+"\n")
                user_login.write(private_key+"\n")"""



    def write_message(self):
        """issue message command, send receipient, send actuall message, """
        self.client_socket.send("message".encode())
        self.client_socket.recv(1024)
        user = input("Which user should receive this message? (you have to write UserID too)")
        message = input("What do you want to tell " + user + "?")
        self.client_socket.send(user.encode()) # sends message receiver
        self.client_socket.recv(1024) # wait for send message
        self.client_socket.send(message.encode())
        self.client_socket.recv(1024) # wait for server confirmation before issuing next command

    def receive_message(self):
        """issue receive, then collect all messages until the "end of messages" command"""
        messages = []  # ["success","message1","message2",...,"end of connection]

        self.client_socket.send("receive".encode())
        while True:
            messages.append(self.client_socket.recv(1024).decode())   # Message Array: [Timestamp, Sender, Message]
            if messages[len(messages)-1] == "end_of_messages":
                break
            elif messages[len(messages)-1] == "Keine neuen Nachrichten.":
                # if no messages are found, inform user and return from function
                print("Keine neuen Nachrichten.")
                return True
            else:
                self.client_socket.send("send next message".encode())

        """Filter first and last message, and convert String arrays to "real" Arrays"""
        print(messages)
        actual_messages = []
        for i in range(1, len(messages)-1):
            actual_messages.append(literal_eval(messages[i]))

        """Sort messages by senders and print them"""
        sorted_after_sender = [[actual_messages[0][1]]]   # [[sender1]]
        new_sender = True
        for message in actual_messages:
            for sender in sorted_after_sender:
                for i in range(0, len(sender)):
                    """If sender exists, append message to sender, else create new sender in sorted_after_sender"""
                    if message[1] == sender[i]:
                        sorted_after_sender[i].append(message)   # [[sender1, message1, message2],[sender2, message1]]
                        new_sender = False
                        break
            if new_sender:
                sorted_after_sender.append(message[1])
                sorted_after_sender[len(sorted_after_sender)-1].append(message)
            new_sender = True

        """Print messages received by each sender"""
        for sender in sorted_after_sender:
            print(sender[0] + " wrote: ")
            del sender[0]
            for i in range(len(sender)):   # [[message 1], [message 2], ..., [message i]]
                print("     "+str(sender[i][0] + " - " + str(sender[i][2])))   # timestamp - message
            print("\n")




    """
    def encrypt_message(self, message):
         user_message = input("Please write your message :)  :")
         print("original string: ", user_message)
         user_message = rsa.encrypt(user_message.encode(), public_key)  # TODO encrypt data
         print("encrypt string: ", user_message)
         user_message = rsa.decrypt(user_message, private_key).decode()
         print("decrypted string: ", user_message)
    """