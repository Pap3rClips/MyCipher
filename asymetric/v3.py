import secrets  # ✅ module sécurisé
import math

# --- Test de primalité : Miller-Rabin ---

def est_premier(n, k=5):
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# --- Génération de nombres premiers sécurisés ---

def generer_nombre_premier(bits):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << bits - 1) | 1  # force MSB et LSB à 1
        if est_premier(n):
            return n

# --- Inverse modulaire ---

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

def generer_cles(bits=2048):
    p = generer_nombre_premier(bits // 2)
    q = generer_nombre_premier(bits // 2)
    while q == p:
        q = generer_nombre_premier(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if math.gcd(e, phi) != 1:
        while True:
            e = secrets.randbelow(phi - 3) + 3
            if math.gcd(e, phi) == 1:
                break

    d = modinv(e, phi)

    return (n, e), (n, d)

# --- Chiffrement et déchiffrement ---

def chiffrer(message, cle_publique):
    n, e = cle_publique
    return [pow(ord(c), e, n) for c in message]

def dechiffrer(blocs, cle_privee):
    n, d = cle_privee
    return ''.join([chr(pow(c, d, n)) for c in blocs])

if __name__ == "__main__":
    pub, priv = generer_cles(bits=2048)

    texte = "Message sécurisé"
    chiffre = chiffrer(texte, pub)
    clair = dechiffrer(chiffre, priv)

    print("Original :", texte)
    print("Chiffré :", chiffre)
    print("Déchiffré :", clair)
