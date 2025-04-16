message = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
brut_key = b"1v4rpRoVE8CzOL9LDB/CLtvluMbWjvXqZKtZ9rePj5QdfWvp1OmfvF/yhC6jIfHX"
ROUND_AMMOUNT = 7

def expend_key(key:bytes,target_size:int)->bytes:
    if (len(key)==0):
        raise ValueError("Clé vide non autorisé")
    return (key*(target_size//len(key)+1))[:target_size]

def slice_message(message:bytes,block_size:int)->list:
    blocks_list = []
    padding = 0
    blocks_ammount = len(message) // block_size + 1
    for i in range(blocks_ammount):
        blocks_list.append(message[padding:padding+block_size])
        padding += block_size
    return blocks_list

def assembly_blocks(blocks_list:list)->bytes:
    return b''.join(blocks_list)

def xor_block(block:bytes,key:bytes)->bytes:
    return bytes([a ^ b for a,b in zip(block, key)])

def generate_round_key(base_key:bytes,round_index:int)->bytes:
    return bytes([round_index^i^b for i,b in enumerate(base_key)])

def my_cipher(message:bytes, brut_key:bytes)->bytes:
    # expension de la clé
    base_key = expend_key(brut_key, 32)
    cipher_message = []
    for b in slice_message(message, 32):
        # round initiale
        cipher_message.append(xor_block(b, base_key))
        # chaine de rounds
        for round_index in range(ROUND_AMMOUNT):
            cipher_message[len(cipher_message)-1] = xor_block(b, generate_round_key(base_key, round_index))
    return assembly_blocks(cipher_message)

print("message d'origine : ")
print(message)
cipher_message = my_cipher(message, brut_key)
print("message chiffré : ")
print(cipher_message)

assert len(expend_key("1v4rp", 32))==32, "Error test 1"
assert len(expend_key("1v4rpRoVE8CzO", 32))==32, "Error test 2"
assert len(expend_key("1v4rpRoVE8CzOL9LDB/CLtvluMbWjvXqZKtZ9rePj5QdfWvp1OmfvF/yhC6jIfHX1v4rpRoVE8CzOL9LDB/CLtvluMbWjvXqZKtZ9rePj5QdfWvp1OmfvF/yhC6jIfHX", 32))==32, "Error test 3"

