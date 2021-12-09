import socket
import threading



class Server:

    #create variables for Server
    def __init__(self):
        self.server_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_loop()

    def client_connect(self, client_server_socket,array):  # client_Server_Socket: Socket Object; array: [Client_IP; Client_Port]
        # TODO give GO! for user Information
        """User logs in"""
        if self.log_in_request(client_server_socket):#TODO Send stored public key
            while True:
                print("stuff successful")
                command = client_server_socket.recv(1024).decode()

                if command == "message":
                    user = client_server_socket.recv(1024).decode()
                    try:
                        # check if file exists
                        file = open("{name}.txt".format(name=user), "r")
                        file.close()
                        user_file = open("{name}.txt".format(name=user), "w")
                        client_server_socket.send("send message".encode())
                        message = client_server_socket.recv(1024).decode()
                        user_file.write("")
                        user_file.write("\n"+ message)
                        user_file.close()
                        client_server_socket.send("end message".encode())
                    except:
                        print("excption")

                #TODO (Maybe) Input validation for log in data
        else:  # Userpassword false
            client_server_socket.close
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
            thread_1 = threading.Thread(target=self.client_connect, args=(client_connected, array,))
            thread_1.start()
            print("Accepted connection from " + str(array[0]) + ":" + str(array[1]))

    def log_in_request(self, client_server_socket):
        """register an account? - This process is automated with client, if client doesnt find local log in data
            it creates an account, if it does, it performs a login"""

        data_from_client = client_server_socket.recv(1024).decode()

        """Request Username and Password  with file name after username"""
        print("Hallo2")
        client_server_socket.send("Username?".encode())  # TODO Check if Username already exists; Change String - "automated process"
        print("Hallo1")
        username_from_client = client_server_socket.recv(1024).decode()

        client_server_socket.send("Password?".encode())
        print(username_from_client)
        password_from_client = client_server_socket.recv(1024).decode()
        user_file_name = "login_data_" + username_from_client + ".txt"


        # TODO Implement safe passwords with salt (maybe pepper)
        # TODO Implement public key for RSA Encryption

        while True:
            if data_from_client == "yes":
                #client_server_socket.send("Public key?")
                #public_key_from_client = client_server_socket.recv(1024).decode()

                """ Create new file if it doesn´t exist """
                print(user_file_name)
                print(user_file_name)
                login_data = open('{}.txt'.format(user_file_name), "w")  # TODO Check Program privileges
                login_data.write(password_from_client)  # TODO Implement public key for RSA Encryption


                login_data.close()
                return True
            else:
                try:
                    login_data = open('{}.txt'.format(user_file_name), 'r')
                    password = login_data.readlines()

                    if password[0] == password_from_client:
                        client_server_socket.send("success")
                        return True  # Log in success
                    else:
                        client_server_socket.send("ERROR: Wrong Password, please try again".encode())
                        """Can only be false, if client data has been manipulated, therefore we close connection"""
                        return False
                except:
                    client_server_socket.send("no login data found, creating new account".encode())
                    data_from_client = "yes"

