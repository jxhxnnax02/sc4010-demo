# SC4010 Attacks on Weak RSA Parameters

Demonstrations of two classic RSA attacks, both run at real **2048-bit** size,
on keys that are generated locally with a deliberately introduced weakness.
Everything is an offline simulation — no network, no real systems.

| Attack | Weakness exploited | Slide reference |
|--------|--------------------|-----------------|
| Batch-GCD (Heninger "Mind your Ps and Qs") | Shared primes from low-entropy key generation | Week 8–9, RSA 2 |
| Håstad broadcast | Tiny `e = 3`, same message sent to ≥ e recipients | Week 8–9, RSA 2 |

## Files

```
keygen.py            # generates keys; one builder per weakness
attacks/
  batch_gcd.py       # product/remainder tree + pairwise reference
  hastad.py          # CRT + integer cube root
victim.py            # encrypts a real AES-protected file for the e=3 demo
run_demo.py          # runs both attacks (+ --scale benchmark)
```

## Setup

```bash
pip install -r requirements.txt     # gmpy2, pycryptodome, sympy
```

## Run

```bash
python run_demo.py --scale          # both attacks + scaling benchmark
python -m attacks.batch_gcd         # shared-prime attack on its own
python -m attacks.hastad            # broadcast attack on its own
```

Run module-style (`python -m attacks.x`) from the project root so the
`keygen` import resolves.

## Notes

- **Batch-GCD** breaks only the weak keys that *share a prime with another key*
  in the set — not every weak key. The hit rate is controlled by `entropy_pool`
  in `keygen.make_mod_pool` (smaller pool → more collisions).
- The `--scale` benchmark times batch-GCD against naive pairwise GCD, showing
  the ~linear vs ~quadratic growth that makes the attack feasible at scale.
- **Håstad** recovers an AES key sent with `e = 3` to three recipients, then
  decrypts a real file — the exploit's practical consequence.

## Fixes (what defeats each attack)

- Shared primes → generate keys with a proper OS CSPRNG.
- Håstad → use `e = 65537` with OAEP padding.