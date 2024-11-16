from Crypto.Cipher import AES
import binascii
import os
import sys
import asyncio
import subprocess


if os.path.exists("secret-key.bin"):
    with open("secret-key.bin", "rb") as keyfile:
        key = keyfile.read()
else:
    key = os.urandom(16)
    with open("secret-key.bin", "wb") as keyfile:
        keyfile.write(key)


class PaddingError(Exception):
    pass

def pad_message(msg):
    val = 16 - (len(msg) % 16)
    return msg + "{}".format(chr(val)).encode()*val

def unpad_message(msg):
    val = msg[-1]
    if not all(x==val for x in msg[-val:]):
        raise PaddingError()
    msg = msg[:-val]
    return msg

mhex = lambda x: binascii.hexlify(x).decode()

async def handle_request(reader, writer):
    print("New connection")
    iv = os.urandom(16)
    secret_msg = b"" + subprocess.check_output("/bin/flag") + b"\n"
    padded_msg = pad_message(secret_msg)

    my_aes = AES.new(key, AES.MODE_CBC, iv)
    crypted_msg = my_aes.encrypt(padded_msg)

    writer.write("I have an encrypted message for you:\n{} (IV was {})\n\n".format(mhex(crypted_msg), mhex(iv)).encode())

    while True:
        writer.write(b"Do you also have an encrypted message for me?!\nIf so, please enter IV and the message seperated by newlines now! (plz give hexlified stuff)\n")
        await writer.drain()

        iv = await reader.readline()
        msg = await reader.readline()

        try:
            iv = binascii.unhexlify(iv.strip())
            msg = binascii.unhexlify(msg.strip())
        except binascii.Error:
            writer.write(b"Couldn't unhexlify your stuff... :(\n")
            writer.close()
            return
        else:
            try:
                my_aes = AES.new(key, AES.MODE_CBC, iv)
                decoded = my_aes.decrypt(msg)
                print(binascii.hexlify(decoded))
                decoded = unpad_message(decoded)
                writer.write(b"OK!\n")
            except PaddingError:
                writer.write(b"Bad padding :(\n")
            except ValueError as e:
                writer.write("Some other error: {}\n".format(e).encode())
                writer.close()
                return

        await writer.drain()

async def run_server():
    server = await asyncio.start_server(handle_request, "0.0.0.0", 1024)
    ip, port = server.sockets[0].getsockname()
    print(f"Serving on {ip}:{port}")
    
    await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run_server())
