# Developer / Author : Hamdy Abou El Anein
# please install crypto and pycrypto for python3
# sudo pip3 install crypto
# sudo pip3 install pycrypto
# install easygui for python 3
# In this version the file must be in the same directory


import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from easygui import *
import sys


def encrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = filename + "encrypted"#(encrypted)"
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))


def decrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = filename

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)


def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def Main():
    image = "./images/encryption.gif"
    msg = "Do you want to encrypt or decrypt a file ?"
    choices = ["Encrypt", "Decrypt", "Exit"]
    reply = buttonbox(msg, image=image, choices=choices)


    if reply == 'Encrypt':
        filename = fileopenbox(msg="Select the file to Encrypt", title="Select the file to Encrypt", default='*', filetypes=None, multiple=False)
        password = passwordbox(msg="Enter a password",title="Enter a password",default="")
        encrypt(getKey(password),filename)

    elif reply == 'Decrypt':
        filename = fileopenbox(msg="Select the file to Decrypt", title="Select the file to Decrypt", default='*', filetypes=None, multiple=False)
        password = passwordbox(msg="Enter a password",title="Enter a password",default="")
        decrypt(getKey(password),filename)

    else:
        sys.exit(0)


if __name__ == '__main__':
    Main()


