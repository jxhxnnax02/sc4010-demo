import argparse
import time
from pathlib import Path

import victim
from attacks import batch_gcd

DATA = Path(__file__).parent / "data"


def banner(title):
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


def demo_shared_prime():
    banner("Attack 1: shared primes (batch-GCD, Heninger 'Ps and Qs')")
    print("Victim: generating 400 x 2048-bit keys (20 from low-entropy devices)...")
    pool = victim.build_shared_prime_dataset()
    weak = sum(k["weak"] for k in pool)
    print(f"Attacker sees only the public (N, e) pairs. Running batch-GCD...")
    t = time.time()
    broken = victim.attack_shared_prime(pool)
    dt = time.time() - t
    print(f"  -> factored {len(broken)} of {weak} weak keys in {dt:.3f}s")
    if broken:
        b = broken[0]
        print(f"  -> example: recovered p = {str(b['p'])[:32]}... and private d")
    print("  Brute-force factoring a single 2048-bit N: infeasible (> age of universe).")


def demo_broadcast():
    banner("Attack 2: tiny e = 3 broadcast (Hastad + CRT)")
    public, real_aes = victim.build_broadcast_dataset()
    print("Victim: same AES-128 key RSA-encrypted to 3 recipients with e = 3,")
    print("        and a file encrypted under that AES key.")
    t = time.time()
    aes_key, plain = victim.attack_broadcast(public)
    dt = time.time() - t
    print(f"  -> recovered AES key matches: {aes_key == real_aes} in {dt:.5f}s")
    print(f"  -> decrypted file: {plain!r}")


def demo_scale():
    banner("Investigation: batch-GCD vs naive pairwise GCD")
    print(f"{'keys':>8} {'pairwise(s)':>14} {'batch(s)':>12}")
    import keygen
    for n in (200, 400, 800, 1600):
        pool = keygen.make_mod_pool(n, max(2, n // 50))
        mods = [k["N"] for k in pool]
        t = time.time(); batch_gcd.pairwise_gcd(mods); tp = time.time() - t
        t = time.time(); batch_gcd.batch_gcd(mods); tb = time.time() - t
        print(f"{n:>8} {tp:>14.3f} {tb:>12.3f}")
    print("Pairwise grows ~n^2; batch-GCD ~n. This is how 11M keys were scanned "
          "in < 2 hours.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", action="store_true", help="run the scaling benchmark too")
    args = ap.parse_args()

    DATA.mkdir(exist_ok=True)
    demo_shared_prime()
    demo_broadcast()
    if args.scale:
        demo_scale()
    print("\nDone.")
