#!/usr/bin/env python

from pwn import *
from Crypto.Util.number import *
from hashlib import md5
import hmac
from random import randrange
from libnum.modular import solve_crt

host, port = "23.100.17.213", 3000

def xor(a, b):
    return "".join([chr(ord(i) ^ ord(j)) for i, j in zip(a, b)])

def Register(username, base):
    r = remote(host, port)
    r.recvuntil("register: ")
    r.sendline("1")
    r.recvuntil("username: ")
    r.sendline(username)
    r.recvuntil("token:")
    r.sendline(str(base))
    r.recvuntil("token: ")
    ret = r.recvline().strip()
    r.close()
    return ret

def Login(cookie_auth):
    r = remote(host, port)
    r.recvuntil("register: ")
    r.sendline("2")
    r.recvuntil("token: ")
    r.sendline(cookie_auth)
    ret = r.recvline()
    r.close()
    return ret

# ~~~~~~~~~~~recover x

p = 337333846325195852023465984016735747017640658020735865443882234978293187151183899366894634062588357161
fac = [ 3 , 8 , 5 , 7 , 53 , 137 , 149 , 173 , 4951 , 38723 , 39659 , 44351 , 44729 , 49253 , 51131 , 52361 , 53693 , 57557 , 62039 , 63367 , 63667 , 13175982811 , 105849660277041952303]

rem = []
mod = []
for pi in fac[:-2]:
    # print pi
    a = randrange(0, p)
    while pow(a, (p - 1)/pi, p) == 1:
        a = randrange(0, p)
    g = pow(a, (p - 1)/pi, p)
    username = "alalala"
    m = Register(username, g).split(":")[-1]
    i = pi - 1
    while True:
        key = long_to_bytes(pow(g, i, p))
        if hmac.new(key, username).hexdigest() == m:
            rem.append(i)
            mod.append(pi)
            break
        i = i - 1

print "rem =", rem
print "mod =", mod
x = solve_crt(rem, mod)
print "x =", x
# x = 1231232342423212224122142

# ~~~~~~~~~~~

my_username = "adm1n+++++++++++"
favor_username = "admin=++++++++++"
cookie = Register(my_username, 3).split(":")[0]
cookie = cookie.decode("hex")

iv = cookie[:16]
second_vector = md5(cookie[16:32]).digest()
third_vector = md5(cookie[32:48]).digest()

payload = xor(second_vector, favor_username)
payload = xor(payload, third_vector)

cookie2 = Register(my_username + payload, 3).split(":")[0]
cookie2 = cookie2.decode("hex")
attack_block = cookie2[48:64]

exploit_cookie = iv + cookie[16:32] + attack_block + cookie[32:]
exploit_cookie = exploit_cookie.encode("hex")

base = 3
shared_key = long_to_bytes(pow(base, x, p))
auth = long_to_bytes(base).encode("hex") + ":" + hmac.new(shared_key, "admin").hexdigest()

exploit_final = exploit_cookie + ":" + auth

print Login(exploit_final)
# Welcome admin! Here, take you flag EFIENCTF{1t_s_k1nd4_h4rd_r1ght?}