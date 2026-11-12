"""
SC4010 weak-RSA demo.  Run from the project root:
    streamlit run app.py
"""
import time
import streamlit as st

import victim

st.set_page_config(page_title="Weak RSA Demo", page_icon="🔓", layout="wide")


def short(n, k=12):
    s = str(n)
    return s if len(s) <= 2 * k else f"{s[:k]}…{s[-k:]}"


st.title("🔓 Weak RSA Attacks")
attack = st.sidebar.radio("Choose an attack", ["Shared primes (batch-GCD)", "e = 3 broadcast (Håstad)"])
if st.sidebar.button("Reset"):
    st.session_state.clear()
    st.rerun()

victim_col, attacker_col = st.columns(2)

# ------------------------------------------------------------ Attack 1
if attack.startswith("Shared"):
    with victim_col:
        st.header("🧑‍💻 Victim")
        st.write("400 devices generate 2048-bit RSA keys. 20 of them boot with low entropy.")
        if st.button("Generate keys", type="primary"):
            with st.spinner("Generating 400 × 2048-bit keys…"):
                st.session_state.pool = victim.build_shared_prime_dataset()
            st.session_state.pop("broken", None)
        pool = st.session_state.get("pool")
        if pool:
            st.success(f"{len(pool)} keys generated ({sum(k['weak'] for k in pool)} from weak devices).")
            st.write("Published public keys (N, e):")
            st.dataframe([{"N": short(k["N"]), "e": 65537} for k in pool], height=300)

    with attacker_col:
        st.header("🕵️ Attacker")
        if not pool:
            st.info("Waiting for the victim to publish keys…")
        else:
            st.write("Only sees the public moduli. Runs batch-GCD across all of them.")
            if st.button("Run batch-GCD", type="primary"):
                t = time.time()
                st.session_state.broken = victim.attack_shared_prime(pool)
                st.session_state.t1 = time.time() - t
            broken = st.session_state.get("broken")
            if broken is not None:
                st.metric("Keys broken", f"{len(broken)} / {len(pool)}", f"in {st.session_state.t1:.3f}s")
                st.dataframe([{"N": short(b["N"]), "p": short(b["p"]), "d": short(b["d"])} for b in broken])
                if broken:
                    b = broken[0]
                    m = int.from_bytes(b"hello", "big")
                    ok = pow(pow(m, 65537, b["N"]), b["d"], b["N"]) == m
                    st.success(f"Recovered private key decrypts correctly: {ok}")

# ------------------------------------------------------------ Attack 2
else:
    with victim_col:
        st.header("🧑‍💻 Victim")
        st.write("Encrypts a file with AES, then sends the AES key to 3 people using RSA with e = 3.")
        secret = st.text_input("Secret file", "Top secret: transfer approved.")
        if st.button("Encrypt & send", type="primary"):
            with st.spinner("Generating 3 × 2048-bit keys…"):
                pub, key = victim.build_broadcast_dataset(secret.encode())
            st.session_state.bc = (pub, key)
            st.session_state.pop("bc_result", None)
        bc = st.session_state.get("bc")
        if bc:
            pub, key = bc
            st.write("🔒 Secret AES key:")
            st.code(key.hex())
            st.write("Sent over the network:")
            for i, (n, c) in enumerate(zip(pub["moduli"], pub["rsa_ciphertexts"]), 1):
                st.text(f"N{i} = {short(n)}\nc{i} = {short(c)}")
            st.text(f"AES ciphertext = {short(pub['aes_ciphertext'], 16)}")

    with attacker_col:
        st.header("🕵️ Attacker")
        if not bc:
            st.info("Waiting for the victim to send something…")
        else:
            st.write("Intercepts the 3 ciphertexts, combines them with CRT, then takes a cube root.")
            if st.button("Run Håstad attack", type="primary"):
                t = time.time()
                st.session_state.bc_result = victim.attack_broadcast(bc[0])
                st.session_state.t2 = time.time() - t
            res = st.session_state.get("bc_result")
            if res:
                rec_key, plain = res
                if rec_key is None:
                    st.error("Attack failed: cube root was not exact.")
                else:
                    st.write("Recovered AES key:")
                    st.code(rec_key.hex())
                    st.write("Decrypted file:")
                    st.code(plain.decode())
                    st.success(f"Key matches: {rec_key == bc[1]} (in {st.session_state.t2 * 1000:.2f} ms)")