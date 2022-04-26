import random
import time
from datetime import datetime, timedelta
import sys
import blessed
from Crypto.Cipher import AES
from Crypto import Random
from secrets import token_hex
from dataclasses import dataclass, field
from collections import namedtuple
from functools import reduce
from typing import Mapping, Tuple, List

private_info = namedtuple("private_info", "q k")
public_info = namedtuple("public_info", "c")
merkle_enc_message = namedtuple("merkle_enc_message", "id c")
session_key = namedtuple("session_key", "id key")
ciphertext = namedtuple("ciphertext", "ctext tag nonce")

def gen_q(key_len = 256, n = 32):
    """We want weak keys, that can be guessed in time q"""
    # we start with 128 AES key
    # time q = 2^n, n = 30/32 bits

    n_key = random.getrandbits(n)
    q = construct_weak_key(n_key, key_len, n)

    return q.to_bytes(key_len//8, "big")

def construct_weak_key(n_bit_secure_key, key_len, n):
    # for example
    # .0110.11111111111 <- "easy" to guess key, 2^n
    # |    |
    # ------
    #   |
    # n bits

    key = 2 ** (key_len - n) - 1 # set all 1s and make space for n_key

    key += n_bit_secure_key << (key_len - n) # insert the n_key

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

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_GCM, ciphertext.nonce)    
    x = cipher.decrypt_and_verify(ciphertext.ctext, ciphertext.tag)  
    return x.decode('UTF-8')

def gen_keys(n, bit_length = 256):
    """
    Bob generates 2^n messages containing id and a symmetrical n-bit long key.
    
    Those messages are then encrypted using AES and used as a public key
    """

    public_key = []
    private_key = {}

    for i in range(1, pow(2, n) + 1):
        qi = gen_q(bit_length, n = n)
        ki = gen_k(bit_length)

        # 32 bytes random identifier
        id_i = token_hex(32)

        # private key has all the info
        private_key[id_i] = (private_info(qi, ki))

    for id, key in private_key.items():
        enc_key = encrypt(key.q, id+ "," + int_binary(int_decode(key.k)))
        public_key.append(public_info(enc_key))

    return private_key, public_key

def int_binary(n):
    return ("{0:b}".format(n))

def int_decode(bytes):
    return int.from_bytes(bytes, "big")

def int_encode(num, length):
    return num.to_bytes(length//8, "big")

def crack_key(c, n, key_len):
    # try to crack the key by bruteforcing every combination
    for q in range(0, 2 ** n):
        weak_key = construct_weak_key(q, key_len, n)
        weak_key = int_encode(weak_key, key_len)
        try:
            data = decrypt(c, weak_key)
        except ValueError as ex:
            continue

        id, symmetrical_key = (data).split(",")
        symmetrical_key = int_encode(int(symmetrical_key, 2), key_len)

        return (id, symmetrical_key, weak_key)

def attack_on_the_protocol(eavesdropped_enc_message, public_key, n, key_len):
    """simulate Eve's attempt to crack established session key"""
    # try attacking
    for key in public_key:
        id, key, weak_k = crack_key(key.c, n, key_len)
        if eavesdropped_enc_message.id == id:
            message = decrypt(eavesdropped_enc_message.c, key)
            return message

@dataclass
class MerkleUser:
    name: str
    """Name of the user"""
    n: int
    """Length of 'weak key' that is cracked to extablish a session key"""
    symmetrical_key_len: int
    """Length of key used to encrypt the communication"""
    session_keys: Mapping[str, session_key] = field(default_factory=dict)
    """List of established session keys with other users"""
    private_keys: Mapping[str, Mapping[str, private_info]] = field(default_factory=dict)
    """Mapping of users to private keys generated for them (private key is in this case a mapping of ids to session keys)"""
    public_keys: Mapping[str, List[public_info]] = field(default_factory=dict)
    """Mapping of users to public keys generated for them (public key is in this case a list of encrypted session keys and their ids)"""

    def generate_keys(self, user):
        """Keys are generated when another user wants to establish connection with this user"""
        self.private_keys[user], self.public_keys[user] =  gen_keys(self.n, self.symmetrical_key_len)
        return self.public_keys[user] 

    def establish_session_key(self, user, public_key):
        """Establish connection with another user by cracking one of the keys in public key list"""
        id, key, weak_key = crack_key(random.choice(public_key).c, self.n, self.symmetrical_key_len)

        self.session_keys[user] = session_key(id, key)
        return id, key, weak_key

    def encrypt_message(self, user, message):
        """Encrypt and send a message using established session key"""
        assert user in self.session_keys, "There's no established key with this user."
        enc_mes = encrypt(self.session_keys[user].key, message)
        # Construct a tuple of (key id, message) to be send to another user
        out_message = merkle_enc_message(self.session_keys[user].id, enc_mes)
        return out_message

    def decrypt(self, user, enc_message):
        """Decrypt a message with a given key id"""
        assert user in self.session_keys or enc_message.id in self.private_keys[user], "There's no session key with this user with that id."
        if not user in self.session_keys: 
            self.session_keys[user] = session_key(enc_message.id, self.private_keys[user][enc_message.id].k)
        # decrypt message using session key with id send by another user
        message = decrypt(enc_message.c, self.session_keys[user].key)
        return message


if __name__=="__main__":
    key_len = 128
    message_to_be_send = "Hello, this is Alice"
    term = blessed.Terminal()

    for n in (8, 12, 16, 20, 24):
        last_n = n
        # Instantiate our communicating sides
        alice = MerkleUser(name="Alice", n=n, symmetrical_key_len=key_len)
        bob = MerkleUser(name="Bob", n=n, symmetrical_key_len=key_len)

        # 1st phase: Alice asks Bob to generate public key for communcation with her
        # To do that, Bob creates 2^n random AES keys (List of those will be his private key)
        # and encrypts them along with some randomly generated ID using an easy to crack key,
        # generating 2^n messages containing encrypt(random_id, key)
        # that will be used as public key and send to Alice.
        # 'Hardness' of the weak key as well as amount of generated messages is controlled by the n parameter
        # This operation takes Bob O(2^n) time and O(2^n) space

        # 1. Alice -(Generate me a public key!)-> Bob 
        # 2. Bob -(bobs_pk_for_alice)-> Alice 
        start_time = time.time()
        bobs_pk_for_alice = bob.generate_keys("Alice")
        generation_time = time.time() - start_time

        # After receiving the publick key, Alice chooses randomly one of the encrypted messages
        # and tries to brute force it, which will take her approx. O(2^n) time

        # 3. Alice cracks randomly selected sessing key from Bob's public key
        start_time = time.time()
        id, key, weak_k = alice.establish_session_key(public_key=bobs_pk_for_alice,user="Bob")
        crack_time = time.time() - start_time

        print("Weak key cracked by Alice: \n", int_binary(int_decode(weak_k)))
        print("Id of the established session key: \n", id)
        print("Established session key: \n",int_binary(int_decode(key)))

        # After cracking the key, Alice establishes it as the session key,
        # uses it to encrypt her messages to bob and sends the ID (in plaintext)
        # along with the encrypted message to Bob.

        # 4. Alice -(id, encrypted message)-> Bob
        enc_message = alice.encrypt_message("Bob", message_to_be_send)
        print(f"Encrypted message from Alice to Bob:\n", enc_message)
        
        # After receiveing the message, Bob uses looks for the session key with a given ID 
        # in his private key, establishes it as session key, and decrypts the message.

        # 5. Bob searches for the key with given ID and decrypts the message
        message = bob.decrypt("Alice", enc_message)
        print(f"Message decrypted by Bob: \n", message)

        # 6. Bob can send a message back using established session key:
        new_message = alice.decrypt("Bob", bob.encrypt_message("Alice", "Test message from bob with established key"))
        print(f"Message send by Bob and decrypted by Alice: \n", new_message)

        print(f"Complexity for n = {term.blue(str(n))}")
        print(f"Space complexity for Bob O(2^n)(in bytes) =\n{sys.getsizeof(bob.private_keys['Alice']) +sys.getsizeof(bob.public_keys['Alice']) }")
        print(f"Time complexity for Bob O(2^n) (in seconds) =\n{term.green(str(generation_time))}")
        print(f"Time complexity for Alice O(2^n) (in seconds) =\n{term.green(str(crack_time))}")

        # its infeasible for larger numbers
        if n < 13:
            last_n_for_eve = n
            # Simulate the attack: Eve eavesdropped on the protocol and
            # captured enc_message - she knows the key ID, but she doesn;t know to which 
            # key in public key list it corresponds to. She has to bruteforce all of the
            # public keys and look for one with ID provided in the message
            # Brute forcing one key takes O(2^n) time and theres 2^n keys, which means
            # This will cost Eve O(2^(2n)) time, while the computational cost for both
            # Alice and Bob is O(2^n + 2^n) ~ O(2^n)
            start_time = time.time()
            eves_message = attack_on_the_protocol(enc_message, bobs_pk_for_alice, n, key_len)
            attack_time = time.time() - start_time
            print(f"Message cracked by Eve: \n", eves_message)
            print(f"Time complexity for Eve O^(2^(2n))(in seconds) =\n{term.red(str(attack_time))}")

    # Estimate space-time requirerments for higher n's
    # x*2^n
    generation_size_modifier = (sys.getsizeof(bob.private_keys['Alice']) +sys.getsizeof(bob.public_keys['Alice'])) / pow(2, last_n)
    generation_modifier = generation_time / pow(2, last_n)
    cracking_modifier = crack_time / pow(2, last_n)
    attack_modifier = attack_time / pow(2, 2* last_n_for_eve)


    # estimate complexity
    for n in (12, 16, 20, 24, 32, 40):
        print(f"Estimated complexity for n = {term.blue(str(n))}")
        print(f"Space complexity for Bob O(2^n)(in bytes) =\n{str(generation_size_modifier * pow(2, n))}")
        td = timedelta(seconds=generation_modifier * pow(2, n))
        print(f"Time complexity for Bob O(2^n) =\n{term.green(str(td))}")
        td = timedelta(seconds=cracking_modifier * pow(2, n)) 
        print(f"Time complexity for Alice O(2^n) =\n{term.green(str(td))}")
        try:
            td = timedelta(seconds=attack_modifier * pow(2, 2 * n))
        except:
            td = str(attack_modifier * pow(2, 2 * n)/60/60/24/365.25/1000) + " thousands years"
        print(f"Time complexity for Eve O(2^(2n)) =\n{term.red(str(td))}")
    

# n = 8
# Space complexity for Bob O(2^n)(in bytes) =
# 11512 ~ 11KB
# Time complexity for Bob O(2^n) (in seconds) =
# 0.02s
# Time complexity for Alice O(2^n) (in seconds) =
# 0.02s
# Time complexity for Eve O^(2^(2n))(in seconds) =
# 1.06s

# n = 12
# Space complexity for Bob O(2^n)(in bytes) =
# 180600 ~ 180KB
# Time complexity for Bob O(2^n) (in seconds) =
# 0.22580432891845703 s
# Time complexity for Alice O(2^n) (in seconds) =
# 0.19811582565307617 s
# Time complexity for Eve O^(2^(2n))(in seconds) =
# 370.4311830997467 ~ 5 mins

# n = 16
# Space complexity for Bob O(2^n)(in bytes) =
# 3184024 ~ 3MB
# Time complexity for Bob O(2^n) (in seconds) =
# 3.66 s
# Time complexity for Alice O(2^n) (in seconds) =
# 3.61 s
# Time complexity for Eve O^(2^(2n)) =
# 16 hours

# n = 20
# Space complexity for Bob O(2^n)(in bytes) =
# 50391864 ~ 50MB
# Time complexity for Bob O(2^n) (in seconds) =
# 60.28 ~ 1min
# Time complexity for Alice O(2^n) (in seconds) =
# 37.65 ~ 1min

# n = 24 
# Space complexity for Bob O(2^n)(in bytes) =
# 813802136 ~ 800MB
# Time complexity for Bob O(2^n) (in seconds) =
# 991.6552839279175 ~ 15mins
# Time complexity for Alice O(2^n) (in seconds) =
# 192.75178217887878 ~ 5min


"""
Estimated complexity for n = 12
Space complexity for Bob O(2^n)(in bytes) =
198682.162109375 ~ 200KB
Time complexity for Bob O(2^n) =
0:00:00.242103
Time complexity for Alice O(2^n) =
0:00:00.047059
Time complexity for Eve O(2^(2n)) =
0:06:10.431183

Estimated complexity for n = 16
Space complexity for Bob O(2^n)(in bytes) =
3178914.59375 ~ 3MB
Time complexity for Bob O(2^n) =
0:00:03.873653
Time complexity for Alice O(2^n) =
0:00:00.752937
Time complexity for Eve O(2^(2n)) =
1 day, 2:20:30.382874

Estimated complexity for n = 20
Space complexity for Bob O(2^n)(in bytes) =
50862633.5 ~ 50MB
Time complexity for Bob O(2^n) =
0:01:01.978455
Time complexity for Alice O(2^n) =
0:00:12.046986
Time complexity for Eve O(2^(2n)) =
280 days, 23:29:38.015625

Estimated complexity for n = 24
Space complexity for Bob O(2^n)(in bytes) =
813802136.0 ~ 800MB
Time complexity for Bob O(2^n) =
0:16:31.655284
Time complexity for Alice O(2^n) =
0:03:12.751782
Time complexity for Eve O(2^(2n)) =
71930 days, 14:26:12 ~ 200 years

Estimated complexity for n = 32
Space complexity for Bob O(2^n)(in bytes) =
208333346816.0 ~ 200 GB
Time complexity for Bob O(2^n) =
2 days, 22:31:03.752686
Time complexity for Alice O(2^n) =
13:42:24.456238
Time complexity for Eve O(2^(2n)) =
12906.348806911552 thousands years

Estimated complexity for n = 40
Space complexity for Bob O(2^n)(in bytes) =
53333336784896.0 ~ 48 TB
Time complexity for Bob O(2^n) =
752 days, 4:32:00.687500
Time complexity for Alice O(2^n) =
146 days, 4:56:20.796875
Time complexity for Eve O(2^(2n)) =
845830475.4097555 thousands years
"""