import random
from math import gcd

# --- Fonction auxiliaire ---

def est_premier(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def generer_nombre_premier(bits=8):
    while True:
        n = random.getrandbits(bits)
        if est_premier(n):
            return n

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Pas d’inverse modulaire')
    return x % m

# --- Génération des clés ---

def generer_cles(bits=8):
    p = generer_nombre_premier(bits)
    q = generer_nombre_premier(bits)
    while q == p:
        q = generer_nombre_premier(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    d = modinv(e, phi)

    cle_publique = (n, e)
    cle_privee = (n, d)
    return cle_publique, cle_privee

# --- Chiffrement et déchiffrement ---

def chiffrer(message, cle_publique):
    n, e = cle_publique
    chiffre = [pow(ord(car), e, n) for car in message]
    return chiffre

def dechiffrer(chiffre, cle_privee):
    n, d = cle_privee
    message = ''.join([chr(pow(c, d, n)) for c in chiffre])
    return message

# Génération des clés
pub, priv = generer_cles(bits=8)

# Message à chiffrer
texte = "hello"
chiffre = chiffrer(texte, pub)
clair = dechiffrer(chiffre, priv)

print("Message original :", texte)
print("Chiffré :", chiffre)
print("Déchiffré :", clair)
