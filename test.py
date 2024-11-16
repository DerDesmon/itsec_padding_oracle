import binascii

a = bytearray(16)
a[0] = 10
a = bytes(a)
print(binascii.hexlify(a))