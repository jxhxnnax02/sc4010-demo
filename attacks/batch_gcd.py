import gmpy2
from gmpy2 import mpz


def product_tree(nums):
    '''
    build a tree from the bottom up. 
    level 0 is the input modulis. 
    each higher level multiplies adjacent pairs and the single top node is the product of all modulis.
    returns the whole tree as a list of levels: tree[0] = leaves, tree[-1] = root 
    '''

    tree = [list(nums)]  #lvl 0, leaves
    while len(tree[-1]) > 1:  #climb until only the root is left on top
        lvl = tree[-1]   #the level most recently built
        nxt = [lvl[i] * lvl[i+1] if i + 1 < len(lvl) else lvl[i] for i in range (0, len(lvl), 2)] #muiltiply adjacent pairs,  if the level is odd length, the last element is carried unchanged
        tree.append(nxt)    #stack the new, shorter level on top
    return tree  #tree[-1][0] is the product of everything

def remainder_tree(tree):
    '''
    Walk the product tree from top down.
    start with the product at the root and calculate parent remainder mod node^2
    '''
    rems = [tree[-1][0]]   #start at the root which is the product of all moduli
    for depth in range(len(tree) - 1, 0, -1):  #descend top level down to just above the leaves
        lvl = tree[depth-1]       #the lvl below the current remainders
        nxt = []                    
        for i in range(len(lvl)):     #each child reduces its parent's remainder (rems[i // 2]) mod child^2
            nxt.append(rems[i // 2] % (lvl[i] ** 2))
        rems = nxt
    return rems


def batch_gcd(moduli):
    '''
    for each modulus, return the prime it shares with some other modulus, or 1 if it doesnt share 
    '''

    moduli = [mpz(n) for n in moduli]
    tree = product_tree(moduli)
    rems = remainder_tree(tree)
    out = []
    for r, n in zip(rems, moduli):
        g = gmpy2.gcd(r // n, n)     #calculate common gcd 
        out.append(g)
    return out 

def recover_private_keys(keys, e = 65537):
    '''
    run batch_gcd for every key that shares a prime, fully factor it and rebuild private exponent d
    '''
    factors = batch_gcd([k["N"] for k in keys])
    broken = []
    for k, g in  zip(keys, factors):
        N = mpz(k["N"])
        if g == 1 or g == N:    #if g shares nothing, key is safe. if g == N, duplicte
            continue

        p = g   #recovered shared prime
        q = N // p  #factorise to get q 
        if p * q != N:   #sanity check
            continue

        phi = (p-1) * (q-1)   
        ee = k.get("e", e) #this key's e  or default value which is 65537
        d = gmpy2.invert(ee, phi) if gmpy2.gcd(ee, phi) == 1 else None    #rebuild private exponent only if inverse exists 
        broken.append({"N": N, "p": p, "q": q, "d": d})
    return broken


def pairwise_gcd(moduli):
    '''
    naive method to get gcd 
    used as comparison against above method
    '''
    moduli = [mpz(n) for n in moduli]
    found = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gmpy2.gcd(moduli[i], moduli[j])
            if g != 1:
                found[i] = g
                found[j] = g
    return found

if __name__ == "__main__":
    import time
    from keygen import make_mod_pool

    pool = make_mod_pool(400, 20)
    t = time.time()
    broken = recover_private_keys(pool)
    dt = time.time() - t
    weak = sum(k["weak"] for k in pool)
    print(f"batch-GCD broke {len(broken)} keys (of {weak} weak) in {dt:.3f}s")


