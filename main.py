import os

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import *

PassWord = '\xd4K\x02pGl\xffv\xad\xdb\x12[I\xba\xdd\xf7\x16\x8a\x8f=\xde\xa5\x08\x06\xb6L,|\x11\x80\xc3\x1e'
salt = b'#\xebN A\x07\\\xa9\xde\xe29z\x0e\t\x80\x9a\x8eOy\x07\x13\x9f\x1f\x05\x0c\x10p\xbb\x0e.\xa8\xbf'
key = PBKDF2(PassWord, salt, dkLen= 32)

print(key)

def encryptTXTtoBin(txt, file, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(txt, AES.block_size))
    with open(file,"wb") as new:
        new.write(cipher.iv)
        new.write(ciphered_data)
def decryptTXTtoBin(file, key):
    with open(file, "rb") as new:
        iv = new.read(16)
        data = new.read()
    cipher = AES.new(key,AES.MODE_CBC, iv = iv)
    file = unpad(cipher.decrypt(data), AES.block_size)
    file = file.decode()
    return file

def deleteUser(userName):
    global s1,s2,s3,s4,d1,d2,d3,d4,link,userPass,information
    s1=s1.replace("\n"+userName+" "+d1[userName],"")
    s2=s2.replace("\n"+d1[userName]+" "+d2[d1[userName]],"")
    a=int(link[d1[userName]][0])
    b=int(link[d1[userName]][1])
    s3=s3.replace("\n"+link[d1[userName]][a+1]+" "+userPass[userName],"")
    s4=s4.replace("\n"+link[d1[userName]][b+1]+":"+d4[link[d1[userName]][b+1]],"")


s1 = decryptTXTtoBin("encrypted.bin",key)
s2 = decryptTXTtoBin("encrypted2.bin",key)
s3 = decryptTXTtoBin("encrypted3.bin",key)
s4 = decryptTXTtoBin("encrypted4.bin",key)
# s1 = ""
# s2 = ""
# s3 = ""
# s4 = ""

# print(s1)
# print(s2)
# print(s3)
# print(s4)

def updateToDefaultfiles():
    s1="""karthik 6545
abhinav 3154
saiteja 6745
chaitanya 9821"""

    s2="""6545 1 2 12 01 .
3154 2 3 . 13 02
6745 3 2 . 03 14
9821 2 1 04 15 ."""

    s3="""12 kart123
13 abhi345
14 tej567
15 chaitu901"""

    s4="""01:mvs karthik,09/02/2005,vijaysai.uchiha@gmail.com,male
02:surabhi abhinav,15/12/2004,abhinavsurabhi@gmail.com,male
03:k sai teja,07/10/2006,capstj@gmail.com,male
04:chaitanya,16/05/2004,chaitanyagattu@gmail.com,female"""


    s1 = memoryview(s1.encode('utf-8')).tobytes()
    s2 = memoryview(s2.encode('utf-8')).tobytes()
    s3 = memoryview(s3.encode('utf-8')).tobytes()
    s4 = memoryview(s4.encode('utf-8')).tobytes()
    encryptTXTtoBin(s1,"encrypted.bin", key)
    encryptTXTtoBin(s2,"encrypted2.bin", key)
    encryptTXTtoBin(s3,"encrypted3.bin", key)
    encryptTXTtoBin(s4,"encrypted4.bin", key)

    s1 = decryptTXTtoBin("encrypted.bin",key)
    s2 = decryptTXTtoBin("encrypted2.bin",key)
    s3 = decryptTXTtoBin("encrypted3.bin",key)
    s4 = decryptTXTtoBin("encrypted4.bin",key)

    print(s1)
    print(s2)
    print(s3)
    print(s4)


d1 = dict([i.split() for i in s1.split("\n")])

d2 = dict([i.split(" ", maxsplit=1) for i in s2.split("\n")])

d3 = dict([i.split() for i in s3.split("\n")])

d4 = dict([i.split(":") for i in s4.split("\n")])

link = dict(zip(d2.keys(), (i.split() for i in d2.values())))

split = dict(zip(d4.keys(), (i.split(",") for i in d4.values())))

passKeys = {}
for i, j in d1.items():
    passKeys[i] = link[j][int(link[j][0]) + 1]

infoKeys = {}
for i, j in d1.items():
    infoKeys[i] = link[j][int(link[j][1]) + 1]

userPass = {}

for i in passKeys:
    userPass[i] = d3[passKeys[i]]

information = {}

for i in infoKeys.keys():
    dic = {}
    lis = d4[infoKeys[i]].split(",")
    dic["name"] = lis[0]
    dic["dob"] = lis[1]
    dic["mail"] = lis[2]
    dic["gender"] = lis[3]
    information[i] = dic


def Reregister(username, password, Name, DateOfBirth, mail, gender):
    global s1, s2, s3, s4, d1, d2, d3, d4, userPass, information, infoKeys
    userPass[username] = password
    information[username] = {"name": Name, "dob": DateOfBirth, "mail": mail, "gender": gender}

    while (True):
        rand1 = str(randint(1000, 9999))
        if rand1 not in d1.keys():
            s1 = s1 + "\n" + username + " " + rand1
            break

    a = randint(1, 3)
    while (True):
        b = randint(1, 3)
        if a != b:
            break

    while (True):
        rand2 = str(randint(1000, 9999))
        rand3 = str(randint(1000, 9999))
        string = ''
        if rand2 not in d3.keys() and rand3 not in d4.keys():
            string = string + rand1 + " " + str(a) + " " + str(b) + " "
            for i in range(1, 4):
                if i == a:
                    string += rand2 + ' '
                elif i == b:
                    string += rand3 + ' '
                else:
                    string += str(randint(1, 1000)) + ' '
            break
    s2 += "\n" + string
    s3 += "\n" + rand2 + " " + password
    s4 += "\n" + rand3 + ":" + Name + "," + DateOfBirth + "," + mail + "," + gender

    d1[username] = rand1
    d2[rand1] = string
    d3[rand2] = password
    d4[rand3] = [Name, DateOfBirth, mail, gender]

    print(s1)
    print(s2)
    print(s3)
    print(s4)

    S1 = memoryview(s1.encode('utf-8')).tobytes()
    S2 = memoryview(s2.encode('utf-8')).tobytes()
    S3 = memoryview(s3.encode('utf-8')).tobytes()
    S4 = memoryview(s4.encode('utf-8')).tobytes()

    for i in infoKeys.keys():
        dic = {}
        lis = d4[infoKeys[i]].split(",")
        dic["name"] = lis[0]
        dic["dob"] = lis[1]
        dic["mail"] = lis[2]
        dic["gender"] = lis[3]
        information[i] = dic

    encryptTXTtoBin(S1,"encrypted.bin", key)
    encryptTXTtoBin(S2,"encrypted2.bin", key)
    encryptTXTtoBin(S3,"encrypted3.bin", key)
    encryptTXTtoBin(S4,"encrypted4.bin", key)
def delENcALL(user):
    global s1, s2, s3, s4, d1, d2, d3, d4, userPass, information
    deleteUser(user)
    s1 = memoryview(s1.encode('utf-8')).tobytes()
    s2 = memoryview(s2.encode('utf-8')).tobytes()
    s3 = memoryview(s3.encode('utf-8')).tobytes()
    s4 = memoryview(s4.encode('utf-8')).tobytes()
    encryptTXTtoBin(s1,"encrypted.bin", key)
    encryptTXTtoBin(s2,"encrypted2.bin", key)
    encryptTXTtoBin(s3,"encrypted3.bin", key)
    encryptTXTtoBin(s4,"encrypted4.bin", key)

print(information)
print(information['karthik']['mail'])
# print(infoKeys)
# delENcALL('22bd1a660v')
# delENcALL('kb')
