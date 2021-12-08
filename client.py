import socket

"""Start Client separately from Server"""
class client:
    """Connect to Server Socket"""
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



    clientSocket.connect(("127.0.0.1", 600))   # TODO use secure socket

    """Communication with Server"""
    while True:
        userMessage = input("Please write your message :)  :")
        print(userMessage)
        userMessage = userMessage.encode()  #TODO encrypt data
        clientSocket.send(userMessage)
