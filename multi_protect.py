import sys
import os
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pss


def print_help():
    print('Usage:\nEncrypt file:\n\t-e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]\nUncipher file:\n\t-d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>\n')
    sys.exit(1)

def get_random(size):
    return get_random_bytes(size)

def get_deadbeef():
    return b'\xDE' + b'\xAD' + b'\xBE' + b'\xEF'

def sha256_digest_from_file(file):
    return SHA256.new(read_from_file(file)).digest()

def sha256(data):
    return SHA256.new(data)

def symetric_encrypt_from_file(file, kc, iv):
    if os.path.isfile(file):
        with open(file, 'rb') as fi:
            return AES.new(kc, AES.MODE_CBC, iv).encrypt(pad(fi.read(), AES.block_size))
    else:
        print('Unable to open %s' % file)
        sys.exit(1)

def symetric_decrypt(c, kc, iv):
    try:
        return AES.new(kc, AES.MODE_CBC, iv).decrypt(c)
    except (ValueError):
        print('Incorrect IV length (it must be 16 bytes long)')
        sys.exit(1)

def asymmetric_encrypt(key, msg):
    try:
        return PKCS1_OAEP.new(key).encrypt(msg)
    except (ValueError):
        print('The message trying to be encrypted with PKCS#1 OAEP is too long')
        sys.exit(1)

def asymmetric_decrypt(key, msg):
    try:
        return PKCS1_OAEP.new(key).decrypt(msg)
    except (ValueError, TypeError):
        print('Failed to decrypted message with PKCS#1 OAEP')
        sys.exit(1)

def genrate_kc_iv():
    return get_random(32), get_random(16)

def import_key(file):
    try:
        return RSA.importKey(read_from_file(file))
    except (ValueError, IndexError, TypeError):
        print('Unable to import %s as RSA key' % file)
        sys.exit(1)

def write_to_file(file, data):
    try:
        with open(file, 'wb') as f:
            f.write(data)
    except (IOError):
        print('Unable to wrtite in %s' % file)
        sys.exit(1)

def read_from_file(file):
    try:
        return open(file, 'rb').read()
    except (IOError):
        print('Unable to read in %s' % file)
        sys.exit(1)

def verify_signature(key, data, s):
    try:
        pss.new(import_key(key)).verify(sha256(data), s)
    except (ValueError, TypeError):
        print('The signature is not authentic')
        sys.exit(1)
    print('The signature is authentic')

def sign(key, data):
    try:
        return pss.new(key).sign(data)
    except (ValueError, TypeError):
        print('Unable to sign the data')
        sys.exit(1)

def unpad_aes(data):
    try:
        return unpad(data, AES.block_size)
    except (ValueError):
        print('Padding is incorrect')
        sys.exit(1)

def gen_r(kc, my_ciph_pub, users_ciph_pub):
    r = sha256_digest_from_file(my_ciph_pub)
    r += asymmetric_encrypt(import_key(my_ciph_pub), kc)
    for ciph in users_ciph_pub:
        r += sha256_digest_from_file(ciph)
        r += asymmetric_encrypt(import_key(ciph), kc)
    return r

def get_r(data, pub_ciph):
    h = sha256_digest_from_file(pub_ciph)
    deadbeef = get_deadbeef()
    x = 0
    while deadbeef not in data[x:x+4] and x < len(data):
        if h in data[x:x+32]:
            return data[x+32:x+32+256]
        else:
            x += 256 + 32
    print('Your cipher public key has not been found in the ciphered file data')
    sys.exit(1)

def get_kc(priv_key, data, pub_ciph):
    return asymmetric_decrypt(priv_key, get_r(data, pub_ciph))

def get_iv_c(data):
    deadbeef = get_deadbeef()
    x = 0
    while deadbeef not in data[x:x+4] and x < len(data):
        x += 256 + 32
    return data[x+4:x+4+16], data[x+4+16:-256]

def cipher(input_file, output_file, my_sign_priv, my_ciph_pub, *users_ciph_pub):
    kc, iv =  genrate_kc_iv()
    c = symetric_encrypt_from_file(input_file, kc, iv)
    r = gen_r(kc, my_ciph_pub, users_ciph_pub)
    data = r + get_deadbeef() + iv + c
    h = sha256(data)
    s = sign(import_key(my_sign_priv), h)
    write_to_file(output_file, data+s)
    sys.exit(0)

def uncipher(input_file, output_file, my_priv_ciph, my_pub_ciph, sender_sign_pub):
    data = read_from_file(input_file)
    verify_signature(sender_sign_pub, data[:-256], data[-256:])
    priv_key = import_key(my_priv_ciph)
    kc = get_kc(priv_key, data, my_pub_ciph)
    iv, c = get_iv_c(data)
    write_to_file(output_file, unpad_aes(symetric_decrypt(c, kc, iv)))
    sys.exit(0)

def parse_args():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-e':
            if len(sys.argv[2:]) >= 4:
                cipher(*sys.argv[2:])
        elif sys.argv[1] == '-d':
            if len(sys.argv[2:]) == 5:
                uncipher(*sys.argv[2:])
        else:
            print_help()
    else:
        print_help()

if __name__ == "__main__":
    parse_args()
