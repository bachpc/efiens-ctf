#!/usr/bin/env python

from pwn import *
from hashlib import md5

host, port = "23.100.17.213", 2000

def xor(a, b):
    return "".join([chr(ord(i) ^ ord(j)) for i, j in zip(a, b)])

def Register(username):
    r = remote(host, port)
    r.recvuntil("register: ")
    r.sendline("1")
    r.recvuntil("username: ")
    r.sendline(username)
    r.recvuntil("cookie: ")
    cookie = r.recvline().strip()
    return cookie

def Login(cookie):
    r = remote(host, port)
    r.recvuntil("register: ")
    r.sendline("2")
    r.recvuntil("cookie: ")
    r.sendline(cookie)
    return r.recvline()

input_username = "adm1n+++++++++++"
favor_username = "admin=++++++++++"
cookie = Register(input_username)
cookie = cookie.decode("hex")

iv = cookie[:16]
second_vector = md5(cookie[16:32]).digest()
third_vector = md5(cookie[32:48]).digest()

payload = xor(second_vector, favor_username)
payload = xor(payload, third_vector)

cookie2 = Register(input_username + payload)
cookie2 = cookie2.decode("hex")
attack_block = cookie2[48:64]

exploit_cookie = iv + cookie[16:32] + attack_block + cookie[32:]
exploit_cookie = exploit_cookie.encode("hex")

print Login(exploit_cookie)
# Welcome admin! Here, take you flag EFIENCTF{bl0ck_c1pher_qwerty123@321}