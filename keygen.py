import random
import gmpy2 
from gmpy2 import mpz

DEFAULT_BITS = 2048

#generate random prime
def rand_prime(rng, bits):
    while True:
        candidate = mpz(rng.getrandbits(bits))
        candidate |= (mpz(1) << (bits - 1))  #force MSB to be 1 so we can get exactly N bit long as 0 would make it n-1bit long 
        candidate |= 1 #force odd
        if gmpy2.is_prime(candidate):
            return candidate

def make_mod_pool(n_keys, n_weak, bits = DEFAULT_BITS, entropy_pool = 16, seed = 0):
    '''
    Simulates the generation of primes with weak entropy. 
    '''
    good = random.SystemRandom()  #good randomness
    keys = []   #will hold one dict per devide
    for i in range(n_keys): 
        if i < n_weak:      #first n_weak devices are the faulty ones with weak p
            boot_state = seed * 1000 + (i % entropy_pool) #only 'entropy_pool' possible seeds so devices collide
            p = rand_prime(random.Random(boot_state), bits // 2) # same seed so same prime 
            weak = True
        else: #rest are healthy devices -> good primes
            p = rand_prime(good, bits//2)
            weak = False
        q = rand_prime(good, bits//2)  # q always strong
        keys.append({"N": p * q, "p" : p, "q" : q, "weak" : weak})
    random.shuffle(keys)
    return keys



def make_broadcast_keys(count = 3, e = 3, bits = DEFAULT_BITS):
    '''
    'count' independent rsa keys all using the same tiny exponent. Each modulus must satisfy gcd(e,phi) = 1
    and be pairwise coprime so the CRT step in hastad's attack is valid
    '''
    good = random.SystemRandom()
    keys = []
    while len(keys) < count:
        p = rand_prime(good, bits//2)
        q = rand_prime(good, bits//2)
        if gmpy2.gcd(e, (p-1)*(q-1)) != 1:    # e must be invertible mod phi otherwise no private key d exists
            continue
        N = p * q
        if any(gmpy2.gcd(N, k["N"]) != 1 for k in keys) :      # new N must share no factor with the key we already made as CRT needs pairwise coprime
            continue
        keys.append({"N": N, "e": e, "p": p, "q": q})
    return keys

if __name__ == "__main__":
    pool = make_mod_pool(10, 4, bits=512, entropy_pool=2)
    print(f"pool: {sum(k['weak'] for k in pool)} weak of {len(pool)}")
    bk = make_broadcast_keys(bits=512)
    print(f"broadcast: {len(bk)} keys, e = {bk[0]['e']}")
