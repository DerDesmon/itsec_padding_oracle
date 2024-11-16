import binascii
import socket
import re
import base64
import time

# TODO: Replace password
PASSWORD = b"016c443fe7431375"

def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf

s = socket.socket()
s.connect(("itsec.sec.in.tum.de", 7011))
s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

# Read password prompt
read_until(s, b": ")
s.sendall(PASSWORD + b"\n")

start = read_until(s, b"Do you")
print(f"Initial message from server:\n{start.decode()}\n")

msg, iv = re.match(rb"I have an encrypted message for you:\n([0-9a-f]*) \(IV was ([0-9a-f]*)\)", start).groups()

iv = binascii.unhexlify(iv)
msg = binascii.unhexlify(msg)

# The server allows you to test the padding of multiple messages per connection.
# You have to send the IV and the encrypted message hexlified.
# If the padding is okay, the server will answer with b"OK!\n" or with an error message.

# Furthermore, the protocol is telnet compatible.
# Therefore, you can connect to the server using socat, nc or telnet.
# This will allow you to test the steps of your exploit manually before implementing them in Python.

# TODO: Implement padding oracle attack here by altering the code below

def xor_bytearrays(a, b):
    return bytearray(x ^ y for (x, y) in zip(a, b))

print(len(msg))

message_string = ""
for block in range(3):
    match block:
        case 0:
            c1 = iv
            c2 = msg[:16]
        case 1:
            c1 = c2
            c2 = msg[16:32]
        case 2:
            c1 = msg[-16:]
            c2 = msg[-16:]
    
    
    print(binascii.hexlify(c1))
    print(binascii.hexlify(c2))
    attack_vector = bytearray(16)
    message = bytearray(16)
    for position in range(16):
        if block == 2:
            position = 4    
        # Create our m2' -> we know how it looks like if the website returns a OK response
        m2_at_position = bytearray(16)
        valid_padding_value = position + 1
        for padding_index in range(valid_padding_value):
            m2_at_position[15 - padding_index] = valid_padding_value
        
        # Adjust bytes left to position in attack with values that result in desired padding to the left -> only need to bruteforce position. We get the values in the attack vector by xor'ing previous message values with our m2_at_position
        attack_vector = xor_bytearrays(message, m2_at_position)
        
        for hex in range(16*16): # Only need to iterate through uft8 values 48 to 123 because that are possible chars for flag
            attack_vector[15 - position] = hex
            # xor c1 and attack vector
            c1_modified = xor_bytearrays(attack_vector, c1)
            # Send c1 and c2 to server -> check response
            s.send(binascii.hexlify(c1_modified) + b"\n", socket.MSG_MORE)
            s.send(binascii.hexlify(c2) + b"\n")
            response = read_until(s, b")\n")
            
            if b"OK!\n" in response:
                # Only gives valid value at position -> only copy it at the position
                #print(f"a : {binascii.hexlify(attack_vector)}")
                #print(f"c1: {binascii.hexlify(c1_modified)}")
                #print(f"m2: {binascii.hexlify(m2_at_position)}") 
                
                message[15 - position] = valid_padding_value ^ attack_vector[15 - position]
                break
    # Concat old message to new message
    message_string = f"{message_string}{bytes(message).decode()}" 
    print(message_string)
print(message_string)