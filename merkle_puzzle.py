import random
from Crypto.Cipher import AES
from Crypto import Random
from collections import namedtuple
from functools import reduce

private_info = namedtuple("private_info", "id q k")
public_info = namedtuple("public_info", "c")
ciphertext = namedtuple("ciphertext", "ctext tag nonce")

def gen_q(key_len = 256, n = 32, prebits = None):
    """We want weak keys, that can be guessed in time q"""
    # we start with 128 AES key
    # time q = 2^n, n = 30/32 bits
    
    dead_bits = key_len - n
    # randomly embed the n-key inside of AES key
    bits_pre_n = random.randrange(0, dead_bits + 1) if prebits == None else prebits
    bits_post_n = dead_bits - bits_pre_n

    n_key = random.getrandbits(n)
    q = construct_weak_key(n_key, key_len, n, prebits)

    return q.to_bytes(key_len//8, "big")

def construct_weak_key(n_bit_secure_key, key_len, n, prebits):
    # for example
    # 11111.0110.11111 <- "easy" to guess key, 2^n
    #      |    |
    #      ------
    #         |
    #       n bits

    key = 2 ** key_len - 1 # set all 1s
    # make space for n_key
    for i in range(key_len - n, key_len - prebits):
        key -= 2 << (i-1)

    key += n_bit_secure_key << (key_len - prebits - n) # insert the n_key
    return key

def gen_k(key_len = 256):
    """generate a 'strong' key"""
    k = Random.get_random_bytes(key_len//8)
    return k 

def encrypt(key, m):
    """Encrypt using AES-256"""

    # AES-256 in GCM mode
    cipher = AES.new(key, AES.MODE_GCM)    
    text, tag = cipher.encrypt_and_digest(m.encode('utf-8'))
    c = ciphertext(text, tag, cipher.nonce)
    
    return c

def gen_keys(n, bit_length = 256, prebits=None):
    public_key = []
    private_key = []

    for i in range(1, pow(2, n) + 1):
        qi = gen_q(bit_length, n = n, prebits=prebits)
        ki = gen_k(bit_length)

        # private key has all the info

        private_key.append(private_info(i, qi, ki))

    shuffled = (private_key)
    random.shuffle(shuffled)

    for key in shuffled:
        enc_key = encrypt(key.q, str(key.id)+ "," + "{0:b}".format(int.from_bytes(key.k, "big")))
        public_key.append(public_info(enc_key))

    return private_key, public_key

def crack_key(c, n=32, key_len=256, q_pos=None):
    if q_pos != None:
        for q in range(0, 2 ** n):
            key = construct_weak_key(q, key_len, n, q_pos)
            key = key.to_bytes(key_len//8, "big")
            try:
                cipher = AES.new(key, AES.MODE_GCM, c.nonce)    
                data = cipher.decrypt_and_verify(c.ctext, c.tag)
            except ValueError as ex:
                continue

            print(data.decode('UTF-8'))

            id, k = (data.decode('UTF-8')).split(",")
            k = int(k, 2).to_bytes(key_len//8, "big")

            return (id, k)
    return (None, None)

sk,pk = gen_keys(16, 128, 0)
print(int.from_bytes(sk[1].q, "big").bit_length())
print("{0:b}".format(int.from_bytes(sk[1].k, "big")))
#print(pk, sk)
id, k = crack_key(pk[1].c, 16, 128, 0)
print(id)
print("{0:b}".format(int.from_bytes(k, "big")))
