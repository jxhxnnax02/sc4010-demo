import json
from pathlib import Path
import gmpy2
from gmpy2 import mpz
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

import keygen
from attacks import batch_gcd, hastad

DATA = Path(__file__).parent / "data"
DATA.mkdir(parents=True, exist_ok=True)   # ensure output dir exists on import


def int_to_bytes(x, length):
    return int(x).to_bytes(length, "big")


def bytes_to_int(b):
    return mpz(int.from_bytes(b, "big"))


# build datasets
#key pool where n_weak keys share primes
def build_shared_prime_dataset(n_keys=400, n_weak=20, e=65537):
    pool = keygen.make_mod_pool(n_keys, n_weak)
    public = [{"N": str(k["N"]), "e": e, "weak": k["weak"]} for k in pool]
    (DATA / "shared_prime_public.json").write_text(json.dumps(public, indent=2))
    return pool

#hybrid scheme -> aes encrypt file, send AES key to 3 recipients with e = 3
def build_broadcast_dataset(secret_file=b"Top secret: transfer approved.\n"):
    aes_key = get_random_bytes(16)                       # the 128-bit secret
    iv = get_random_bytes(16)
    ct = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(secret_file, 16))

    keys = keygen.make_broadcast_keys(count=3, e=3)
    m = bytes_to_int(aes_key)
    rsa_cts = [str(pow(m, k["e"], k["N"])) for k in keys]
    public = {
        "e": 3,
        "moduli": [str(k["N"]) for k in keys],
        "rsa_ciphertexts": rsa_cts,
        "aes_iv": iv.hex(),
        "aes_ciphertext": ct.hex(),
    }
    (DATA / "broadcast_public.json").write_text(json.dumps(public, indent=2))
    return public, aes_key


# --------------------------------------------------------------- attacker side

#batch gcd finds shared factors -> rebuilds private keys
def attack_shared_prime(pool):
    broken = batch_gcd.recover_private_keys(pool)
    return broken


#hastad: CRT + cube root recovers AES key, then decrypt file. 
def attack_broadcast(public):
    moduli = [mpz(n) for n in public["moduli"]]
    cts = [mpz(c) for c in public["rsa_ciphertexts"]]
    m = hastad.hastad_attack(cts, moduli, e=public["e"])
    if m is None:
        return None, None
    aes_key = int_to_bytes(m, 16)
    iv = bytes.fromhex(public["aes_iv"])
    ct = bytes.fromhex(public["aes_ciphertext"])
    plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
    return aes_key, plain


if __name__ == "__main__":
    print("Building datasets (this generates real 2048-bit keys)...")
    pool = build_shared_prime_dataset()
    bc, real_aes = build_broadcast_dataset()
    print("Datasets written to data/.")