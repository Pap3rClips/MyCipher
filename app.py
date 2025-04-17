import os
SBOX = [((i * 17 + 31) ^ (i << 1)) % 256 for i in range(256)]
def substitute(b):
    return SBOX[b]
def generate_iv(length=8):
    return list(os.urandom(length))
def derive_key(password, salt, iv, length=256, rounds=300):
    base = [ord(c) for c in password] + salt + iv
    mem = [0] * 1024 
    for i in range(len(mem)):
        mem[i] = (base[i % len(base)] * (i + 1)) % 256
        for r in range(3):
            mem[i] = (mem[i] * 73 + base[i % len(base)] * r + i) % 256

    k = []
    for i in range(length):
        val = (base[i % len(base)] + salt[i % len(salt)] + iv[i % len(iv)]) % 256
        for r in range(rounds):
            j = (val + r * 17 + i * 11) % len(mem)
            val = (val * 31 + mem[j]) % 256
        k.append(val)
    return k
def hmac_simul(data, key_stream):
    mac = [0] * 16
    for i, b in enumerate(data):
        for j in range(16):
            k = key_stream[(i + j) % len(key_stream)]
            mac[j] = (mac[j] + b * (k + i + j) + j * 13) % 256
            mac[j] = mac[j] ^ ((b + k * j + i) % 256)
    return mac
def chiffre(message, password):
    iv = generate_iv()
    salt = list(os.urandom(8))
    key_stream = derive_key(password, salt, iv, length=len(message), rounds=300)
    res = []
    prev = sum(iv + salt) % 256

    for i, c in enumerate(message):
        char = ord(c)
        k = key_stream[i]
        sub = substitute((char ^ k ^ prev) % 256)
        res.append(sub)
        prev = (sub * 17 + i * 31 + prev * 13) % 256

    mac = hmac_simul(res, key_stream)
    full = iv + salt + res + mac
    return ''.join(f'{b:02x}' for b in full)
def dechiffre(hexstr, password):
    data = [int(hexstr[i:i+2], 16) for i in range(0, len(hexstr), 2)]
    iv = data[:8]
    salt = data[8:16]
    mac = data[-16:]
    chiffré = data[16:-16]

    key_stream = derive_key(password, salt, iv, length=len(chiffré), rounds=300)
    if hmac_simul(chiffré, key_stream) != mac:
        return "[ERREUR : Message modifié ou clé incorrecte]"

    res = ""
    prev = sum(iv + salt) % 256
    inv_sbox = [0] * 256
    for i, s in enumerate(SBOX):
        inv_sbox[s] = i

    for i, c in enumerate(chiffré):
        uns = inv_sbox[c]
        k = key_stream[i]
        m = (uns ^ k ^ prev) % 256
        res += chr(m)
        prev = (c * 17 + i * 31 + prev * 13) % 256

    return res
def main():
    mode = input("Chiffrer (c) ou Déchiffrer (d) ? ").strip().lower()
    if mode == "c":
        msg = input("Message à chiffrer : ")
        key = input("Clé (même simple) : ")
        print("\nMessage chiffré :")
        print(chiffre(msg, key))
    elif mode == "d":
        hexstr = input("Texte chiffré (hex) : ").strip()
        key = input("Clé utilisée : ")
        print("\nMessage déchiffré :")
        print(dechiffre(hexstr, key))
    else:
        print("Option invalide.")
main()
