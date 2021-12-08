import socket
import threading



class Server:

    #create variables for Server
    def __init__(self):
        self.server_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_loop()






    def client_connect(self, client_Server_Socket,array):  # TODO give GO! for user Information # TODO Log in User
        while True:
            data_From_Client = client_Server_Socket.recv(1024).decode()


            print(str(array[0]) +":"+str(array[1]) + " wrote: " +data_From_Client)  # TODO Store data in user   #TODO Send stored data

    def main_loop(self):

        self.server_Socket.bind(("127.0.0.1", 600))  # TODO use secure socket
        print("Server Listening...")
        self.server_Socket.listen()

        while True:


            (client_Connected, client_Address) = self.server_Socket.accept()

            array = []
            for item in client_Connected.getpeername():
                array.append(item)

            thread_1 = threading.Thread(target=self.client_connect, args=(client_Connected, array,))
            thread_1.start()

            #self.client_connect(client_Connected)

            print("Accepted connection from " + str(array[0]) + ":" + str(array[1]))
