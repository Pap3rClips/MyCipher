import secrets
import math

# --- Test de primalité (Miller-Rabin) ---

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

# --- Génération de nombre premier sécurisé ---

def generer_nombre_premier(bits):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << bits - 1) | 1
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

# --- Génération des clés RSA ---

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

# --- Padding (remplissage) simple type OAEP ---

def pad_message_bloc(message_bloc, block_size):
    message_bytes = message_bloc.encode('utf-8')
    padding_length = block_size - len(message_bytes)
    if padding_length <= 0:
        raise ValueError("Message bloc trop long pour la taille RSA")

    padding = secrets.token_bytes(padding_length)
    padded = padding + message_bytes
    return int.from_bytes(padded, byteorder='big')

def unpad_message_bloc(bloc_dechiffre, block_size):
    data = bloc_dechiffre.to_bytes(block_size, byteorder='big')
    for i in range(len(data)):
        try:
            return data[i:].decode('utf-8')
        except UnicodeDecodeError:
            continue
    return ''

# --- Chiffrement sécurisé (avec padding) ---

def chiffrer_securise(message, cle_publique, block_size_bytes):
    n, e = cle_publique
    blocs = []
    for i in range(0, len(message), block_size_bytes - 11):  # espace réservé au padding
        bloc = message[i:i + block_size_bytes - 11]
        padded = pad_message_bloc(bloc, block_size_bytes)
        chiffre = pow(padded, e, n)
        blocs.append(chiffre)
    return blocs

# --- Déchiffrement sécurisé (avec dépadding) ---

def dechiffrer_securise(blocs, cle_privee, block_size_bytes):
    n, d = cle_privee
    message = ''
    for bloc in blocs:
        decrypted = pow(bloc, d, n)
        message += unpad_message_bloc(decrypted, block_size_bytes)
    return message

# --- Hachage simple "maison" (non sécurisé) ---

def hacher_message_simple(message):
    """Retourne un haché simple du message comme entier (non sécurisé)."""
    h = 0
    for i, c in enumerate(message):
        h = (h * 31 + ord(c) * (i + 1)) % (10**9 + 7)  # Simple modulo large
    return h

# --- Signature numérique avec RSA (hachage simple) ---

def signer_message(message, cle_privee):
    """Signe le haché du message avec la clé privée RSA."""
    n, d = cle_privee
    hash_int = hacher_message_simple(message)
    signature = pow(hash_int, d, n)
    return signature

def verifier_signature(message, signature, cle_publique):
    """Vérifie que la signature RSA correspond au message et à la clé publique."""
    n, e = cle_publique
    hash_int = hacher_message_simple(message)
    hash_from_signature = pow(signature, e, n)
    return hash_int == hash_from_signature

# --- Exemple d'utilisation ---

if __name__ == "__main__":
    print("🔐 Génération des clés RSA...")
    cle_pub, cle_priv = generer_cles(bits=2048)
    block_size_bytes = (cle_pub[0].bit_length() + 7) // 8

    texte_original = "Voici un message sécurisé."
    print("📤 Message original :", texte_original)

    chiffre = chiffrer_securise(texte_original, cle_pub, block_size_bytes)
    print("🔒 Chiffré :", chiffre)

    decrypte = dechiffrer_securise(chiffre, cle_priv, block_size_bytes)
    print("📥 Déchiffré :", decrypte)

    # --- Signature numérique ---
    print("\n🖋️ Signature du message...")
    signature = signer_message(texte_original, cle_priv)
    print("🔏 Signature :", signature)

    print("\n🔍 Vérification de la signature...")
    valide = verifier_signature(texte_original, signature, cle_pub)
    print("✅ Signature valide ?" , valide)

    print("\n🔍 Test avec message modifié...")
    message_modifie = texte_original + " (modifié)"
    valide_modifie = verifier_signature(message_modifie, signature, cle_pub)
    print("❌ Signature valide pour le message modifié ?", valide_modifie)
