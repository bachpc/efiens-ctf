# Writeup for *EFIENS CTF 2019*

## (Crypto) *!Stream Cipher*

*Đề bài*: [crypto1.py](./crypto1/crypto1.py)

*Output*: ed139bafa3833c178afd29f21dc16f94a869c49b90d06373b99e5b8b6db530b5

Output có 2 block, block đầu là `E(IV)`, block sau là `plaintext XOR E(IV)` theo `AES OFB mode`, vậy nên chỉ cần `XOR` 2 block lại là ra flag.

```python
from Crypto.Cipher import XOR

out = "ed139bafa3833c178afd29f21dc16f94a869c49b90d06373b99e5b8b6db530b5".decode("hex")

encryptedIV = out[:16]
cipher = out[16:]

t = XOR.new(encryptedIV)
print t.decrypt(cipher)
# Ez_43S_d3crypt_!
```

## (Crypto) *Cookie1*

Đề bài:

- [cookiegen.py](./cookie1/cookiegen.py)
- [service.py](./cookie1/service.py)

Cho dịch vụ gồm 2 lựa chọn:

- Register: Người dùng gửi lên `username`, server trả về cookie là chuỗi mã hóa của `"cookie?username=" + username + "=" + secret"` sử dụng thuật toán tương tự `AES CBC_Mode`.

```python
# Encrypt/Register
def encrypt(self, plaintext, iv):
    plaintext = pad(plaintext)
    temp = iv
    ciphertext = ""
    for i in range(0, len(plaintext), 16):
        aes_obj = AES.new(self.key, AES.MODE_ECB)
        ciphertext_block = aes_obj.encrypt(xor(plaintext[i:i+16], temp))
        ciphertext += ciphertext_block
        temp = md5(ciphertext_block).digest()
    return iv + ciphertext

def register(self, username):
    if "admin" in username:
        return "[-] Invalid username!"
    plaintext = "cookie?username=" + username + "=" + self.secret
    cipher_obj = Cipher(self.key)
    cookie = cipher_obj.encrypt(plaintext, self.iv)
    return cookie.encode("hex")
```

- Login: Người dùng gửi `cookie`, server decrypt và trả về `flag` nếu `username == "admin"`.

```python
# Decrypt/Login
def decrypt(self, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    temp = iv
    plaintext = ""
    for i in range(0, len(ciphertext), 16):
        aes_obj = AES.new(self.key, AES.MODE_ECB)
        plaintext_block = xor(aes_obj.decrypt(ciphertext[i:i+16]), temp)
        plaintext += plaintext_block
        temp = md5(ciphertext[i:i+16]).digest()
    return unpad(plaintext)

def login(self, cookie):
        cookie = cookie.decode("hex")
        cipher_obj = Cipher(self.key)
        try:
            plaintext = cipher_obj.decrypt(cookie)
        except:
            return None

        plaintext = plaintext.split("=")
        if plaintext[0] != "cookie?username":
            return None
        elif plaintext[-1] != self.secret:
            return None
        else:
            return plaintext[1]
```

Đặt `pt = "cookie?username=" + username + "=" + secret"` và `ct` là cookie nhận được khi register.

```
input_username = "adm1n+++++++++++"
favor_username = "admin=++++++++++"
```

```
ct[:16]       = iv

ct[16:32]     = E("cookie?username=" XOR iv)
second_vector = md5(ct[16:32])

ct[32:48]     = E(username[:16] XOR second_vector)
third_vector  = md5(ct[32:48])

ct[48:64]     = E(16_bytes_after XOR third_vector)
```

Ta cần `username == favor_username` hay `cookie[32:48] == E(favor_username XOR second_vector)`, để ý

```
  E(favor_username XOR second_vector)
= E((favor_username XOR second_vector XOR third_vector) XOR third_vector)
```

Nên nếu ta chọn

```
payload = favor_username XOR second_vector XOR third_vector
username = input_username + payload
```

Thì `cookie[48:64] = E(favor_username XOR second_vector)`.

Exploit code:

```python
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
```

[solve.py](./cookie1/solve.py)

## (Crypto) *Cookie2*

Đề bài:

- [cookiegen.py](./cookie2/cookiegen.py)
- [service.py](./cookie2/service.py)

Phần cookie tương tự bài `Cookie1` nhưng có thêm phần `auth token`.

```python
def register(self, username, base):
    if "admin" in username:
        return "[-] Invalid username!"
    plaintext = "cookie?username=" + username + "=" + self.secret
    cipher_obj = Cipher(self.key)
    cookie = cipher_obj.encrypt(plaintext, self.iv)
    return cookie.encode("hex") + ":" + self.gen_auth_token(username, base)

def gen_auth_token(self, username, base):
    if base < 2 or base >= self.p-1:
        return None
    shared_key = long_to_bytes(pow(base, self.x, self.p))
    return long_to_bytes(base).encode("hex") + ":" + hmac.new(shared_key, username).hexdigest()

def login(self, cookie):
    cookie = cookie.split(":")
    try:
        assert len(cookie) == 3
    except:
        return None
    base = bytes_to_long(cookie[1].decode("hex"))
    auth_token = cookie[2]
    cookie = cookie[0].decode("hex")

    cipher_obj = Cipher(self.key)
    try:
        plaintext = cipher_obj.decrypt(cookie)
    except:
        return None

    plaintext = plaintext.split("=")
    if plaintext[0] != "cookie?username":
        return None
    elif plaintext[-1] != self.secret:
        return None
    elif self.verify_auth_token(plaintext[1], base, auth_token) != True:
        return None
    else:
        return plaintext[1]

def verify_auth_token(self, username, base, auth_token):
    if base < 2 or base >= self.p-1:
        return False
    shared_key = long_to_bytes(pow(base, self.x, self.p))
    if hmac.new(shared_key, username).hexdigest() == auth_token:
        return True
    else:
        return False
```

Trong mục `Register` cho người dùng nhập `base` bất kỳ trong khoảng `[2, p - 1)` và tính `share_key = long_to_bytes(pow(base, x, p))` với `x` chưa biết, sau đó tạo `auth_token = hmac(share_key, username)`.

Factor `p - 1` ta được:

```
2^3 * 3 * 5 * 7 * 53 * 137 * 149 * 173 * 4951 * 38723 * 39659 * 44351 * 44729 * 49253 * 51131 * 52361 * 53693 * 57557 * 62039 * 63367 * 63667 * 13175982811 * 105849660277041952303
```

Có khá nhiều ước nguyên tố nhỏ nên ta có thể áp dụng `Small Subgroup Confinement Attack` cho bài này.

```python
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
```

Done.

Exploit code:

```python
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
```

[solve.py](./cookie2/solve.py)
