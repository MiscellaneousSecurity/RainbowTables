'''Hashing occurs here.'''
from hashlib import sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256, md5
from passwordfetcher import fetch_passwords

def hash_sha1(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha1(password).hexdigest() if in_hex else sha1(password).digest())
    return new_set

def hash_sha256(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha256(password).hexdigest() if in_hex else sha256(password).digest())
    return new_set

def hash_sha224(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha224(password).hexdigest() if in_hex else sha224(password).digest())
    return new_set

def hash_sha384(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha384(password).hexdigest() if in_hex else sha384(password).digest())
    return new_set

def hash_sha512(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha512(password).hexdigest() if in_hex else sha512(password).digest())
    return new_set

def hash_sha3_224(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha3_224(password).hexdigest() if in_hex else sha3_224(password).digest())
    return new_set

def hash_sha3_256(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha3_256(password).hexdigest() if in_hex else sha3_256(password).digest())
    return new_set

def hash_sha3_384(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha3_384(password).hexdigest() if in_hex else sha3_384(password).digest())
    return new_set

def hash_sha3_512(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(sha3_512(password).hexdigest() if in_hex else sha3_512(password).digest())
    return new_set

def hash_shake_128(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(shake_128(password).hexdigest() if in_hex else shake_128(password).digest())
    return new_set

def hash_shake_256(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(shake_256(password).hexdigest() if in_hex else shake_256(password).digest())
    return new_set

def hash_md5(hash_set:set|None = None, in_hex:bool=True) -> set:
    if hash_set == None:
        hash_set = fetch_passwords()
    new_set = set()
    for password in hash_set:
        new_set.add(md5(password).hexdigest() if in_hex else md5(password).digest())
    return new_set


if __name__ == '__main__':
    print(hash_sha1())