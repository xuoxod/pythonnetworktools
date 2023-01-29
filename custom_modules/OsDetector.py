import socket

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
""" 
host = input("Enter the IP Address of the Host : ")
port = 80
 """


def get_operating_system(host, port):
    try:
        # Connect to the host on specified port
        conection = s.connect((host, port))

        # Send Data to the host
        s.send("GET / HTTP/1.0\r\n\r\n".encode())

        # Receive data from the host and save into a variable
        received_data = s.recv(1024)

        # Close Socket Connection (Clean up)
        s.close()

        print("[*] Sending data to " + str(host) + ":" + str(port))

        if "Windows" in str(received_data):
            print("[*] The Operating System is Windows")

        elif "Linux" in str(received_data):
            print("[*] The Operating System is Linux")

        # If OS not found return None as result
        else:
            print("[*] Unknown Operating System")
            print("{}".format(str(received_data)))
            return None
    except ConnectionRefusedError as cre:
        print("Host {} refused connection on port {}".format(host, port))

    # Call the function and Pass Host IP Address & Port number as arguments get_operating_system('192.168.100.2', 80)
