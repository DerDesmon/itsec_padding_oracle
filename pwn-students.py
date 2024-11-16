import binascii
import socket
import re
import base64

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

# aufgbae : herausfinden was wir schicken müssen, ob ganze message das komplette oder nur 2 sachen
#kopier script schick 32 byte als string , und was ist die response
#

# For Schleife, die c1, c2 automatisch aus message extrahiert
#wurde schon davor mit iv gemacht
#muss um 1 erhöhen wenn padding fehler detected

message_string = ""
for block in range(6):
    if block is 0:
        # First iteration: use iv as 'c1'
        c1 = iv
        c2 = msg[:16] 
    else:
        # Block - 1 because we are we iterate over two blocks of six total blocks five times (-> prevent out of bounds)
        offset = (block - 1) * 16
        c1, c2 = msg[offset: 16 + offset], msg[16 + offset : 32 + offset]
        
    attack_vector = bytearray(16)
    message = bytearray(16)
    for position in range(16):
        # Need to fill bytes left to position in attack with valid padding (e.g. attack postion = 3 -> c1 should look like this: ... 0x03/0x03/0x03)
        m2_at_position = bytearray(16)
        for padding_index in range(position):
            m2_at_position[15 - padding_index] = position
        for padding_index in range(position):
            tmp = bytes([a^ b for a, b in zip(m2_at_position, message)])
            attack_vector[15 - padding_index] = tmp[15 - padding_index]
        for hex in range(16):        
            attack_vector[15 - position] = hex
            c1 = bytes([a^ b for a, b in zip(c1, attack_vector)]) # Need to convert attack vector to bytes so it can be xor'd
            # Send c1 and c2 to server -> check response
            s.send(binascii.hexlify(c1 + c2) + b"\n")
            response = read_until(s, b"\n")
            if b"OK!\n" in response:
                message_at_position = bytes([a^ b for a, b in zip(m2_at_position, attack_vector)]) # Only gives valid value at position
                message[15 - position] = message_at_position[15 - position]
                print(f"block: {block}, position: {15 - position}, message char: {message[15 - position]}")
                break
    message_string += binascii.hexlify(bytes(message))
print(message_string)