import random

# --- Test de primalité Miller-Rabin ---

def est_premier(n, k=5):  # k = nombre de rounds de test
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # Écriture de n-1 comme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
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

def generer_nombre_premier(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # force MSB et LSB à 1 pour garantir la taille et l'impair
        if est_premier(n):
            return n

# --- Inverse modulaire (Extended Euclidean Algorithm) ---

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

# --- Génération des clés RSA ---

def generer_cles(bits=2048):
    p = generer_nombre_premier(bits // 2)
    q = generer_nombre_premier(bits // 2)
    while q == p:
        q = generer_nombre_premier(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if egcd(e, phi)[0] != 1:
        # choisir un autre 'e' aléatoire
        while True:
            e = random.randrange(3, phi, 2)
            if egcd(e, phi)[0] == 1:
                break

    d = modinv(e, phi)

    return (n, e), (n, d)

# --- Chiffrement et déchiffrement ---

def chiffrer(message, cle_publique):
    n, e = cle_publique
    blocs = [pow(ord(c), e, n) for c in message]
    return blocs

def dechiffrer(blocs, cle_privee):
    n, d = cle_privee
    message = ''.join([chr(pow(c, d, n)) for c in blocs])
    return message

if __name__ == "__main__":
    pub, priv = generer_cles(bits=2048)

    texte = "Message sécurisé"
    chiffre = chiffrer(texte, pub)
    clair = dechiffrer(chiffre, priv)

    print("Original :", texte)
    print("Chiffré :", chiffre)
    print("Déchiffré :", clair)
