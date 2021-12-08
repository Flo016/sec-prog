import socket

class client:

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



    clientSocket.connect(("127.0.0.1", 600))   # TODO use secure socket

    #AHHAA
    while True:

        userMessage = input("Please write your message :)  :") # TODO (Maybe) Inputvalidation
        print(userMessage)
        userMessage = userMessage.encode()  #MAC

        print("AÖKDSJHLÖKSAJÖKLASJÖDLASJÖLDKLASD")
        clientSocket.send(userMessage)
