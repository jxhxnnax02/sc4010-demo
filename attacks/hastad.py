import gmpy2 
from gmpy2 import mpz
from sympy.ntheory.modular import crt


def hastad_attack(ciphertexts, moduli, e = 3):
    #need at least e ciphertexts to pin it down with CRT. Fewer than e and the cube root won't be exact
    assert len(ciphertexts) >= e, f"need at least {e} ciphertexts"
    c = ciphertexts[:e]  #take exactly e ciphertexts 
    n = moduli[:e]  #take the matching e moduli
    x, _ = crt(n, c)   #sympy crt takes (moduli, residues) -> returns (solution, product)
    m, exact = gmpy2.iroot(x, e)  #take cubic root of x to find message
    return m if exact else None  #exact = False means recovery failed


if __name__ == "__main__":
    import time
    from keygen import make_broadcast_keys
    from gmpy2 import mpz

    keys = make_broadcast_keys(count=3, e = 3)
    msg = "secret!!"
    m = mpz(int.from_bytes(msg.encode(), "big"))   # text -> bytes -> integer

    ciphertexts = [pow(m, k["e"], k["N"]) for k in keys]
    t = time.time()
    deciphered = hastad_attack(ciphertexts, [k["N"] for k in keys], e = 3)
    length = (deciphered.bit_length() + 7) // 8        # how many bytes
    text = int(deciphered).to_bytes(length, "big").decode()
    print(text)   
    print(f"recovered message correctly: {deciphered == m} in {time.time() - t:.5f}s")