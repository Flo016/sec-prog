import socket
import threading



class Server:

    #create variables for Server
    def __init__(self):
        self.server_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_loop()

    def client_connect(self, client_server_socket,array):  # client_Server_Socket: Socket Object; array: [Client_IP; Client_Port]
        # TODO give GO! for user Information # TODO Log in User

        """User logs in"""
        if self.log_in_request(client_server_socket):
            print("stuff successful")
            """ Wait for messages, one per loop cycle"""
            #while True:
                #data_from_client = client_server_socket.recv(1024).decode()
                #print(str(array[0]) + ":" + str(
                    #array[1]) + " wrote: " + data_from_client)  # TODO Store data in user   #TODO Send stored data
                # TODO (Maybe) Input validation for log in data
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
        client_server_socket.send("Username?".encode())  # TODO Check if Username already exists; Change String - "automated process"
        username_from_client = client_server_socket.recv(1024).decode()
        client_server_socket.send("Password?".encode())
        password_from_client = client_server_socket.recv(1024).decode()
        user_file_name = "login_data_" + username_from_client  # Create User filename

        # TODO Implement safe passwords with salt (maybe pepper)
        # TODO Implement public key for RSA Encryption

        while True:
            if data_from_client == "yes":
                #client_server_socket.send("Public key?")
                #public_key_from_client = client_server_socket.recv(1024).decode()

                """ Create new file if it doesn´t exist """

                login_data = open("{name}.txt".format(name=user_file_name), "w")  # TODO Check Program privileges
                login_data.write(password_from_client)  # TODO Implement public key for RSA Encryption

                login_data.close()
                return True
            else:
                try:
                    with open("{name}.txt".format(name=user_file_name), 'r') as login_data:
                        password = login_data.read()
                        if password == password_from_client:
                            client_server_socket.send("success")
                            return True  # Log in success
                        else:
                            client_server_socket.send("ERROR: Wrong Password, please try again".encode())
                            """Can only be false, if client data has been manipulated, therefore we close connection"""
                            return False
                except:
                    client_server_socket.send("no login data found, creating new account".encode())
                    data_from_client = "yes"
