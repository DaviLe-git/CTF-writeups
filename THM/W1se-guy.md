# CTF Writeup — W1se Guy

## 📌 Overview

* **Platform:** TryHackMe
* **Difficulty:** Easy
* **Date:** March 2026
* **Objective:** Recover two flags from an XOR-encrypted TCP service

W1se Guy is a cryptography challenge that presents a TCP service on port 1337. Upon connection, the server issues a dynamically generated XOR-encoded ciphertext and prompts for the encryption key. The challenge revolves around performing a **known-plaintext attack** to recover the repeating XOR key and decrypt both flags. Source code for the service was provided as part of the challenge.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

Connectivity to the target was confirmed before proceeding.

```bash
ping 10.82.139.121
```

The challenge specification indicated that a TCP service was listening on port **1337**. A direct connection was established using Netcat to observe the service behaviour.

```bash
nc 10.82.139.121 1337
```

**Service response:**

```
This XOR encoded text has flag 1: 360e264d335327075837273e1f77371672085d2023281905220e0a125e161032120636103e24443e
What is the encryption key?
```

**Key observations:**

* The service delivers a hex-encoded XOR ciphertext on each connection.
* The ciphertext is **dynamically regenerated** on every new session — a critical detail that invalidates any key recovered from a previous connection.
* The service prompts for the key before revealing the decrypted flag.
* The downloaded source code confirmed the encryption mechanism but did not expose the key directly.

---

### 2. Further Enumeration

#### Understanding the Cipher

Reviewing the source code confirmed that the plaintext flag follows the standard TryHackMe format: `THM{...}`. This is the essential known-plaintext component that makes the attack viable.

Key properties of the cipher identified during analysis:

* **Algorithm:** Repeating-key XOR
* **Key length:** 5 bytes (inferred from source code review)
* **Known plaintext:** The flag prefix `THM{` (4 bytes) and suffix `}` (1 byte) cover the full 5-byte key — one byte per key position.

---

## 💥 Exploitation

**Vulnerability type:** Known-Plaintext Attack against a repeating-key XOR cipher  
**Location:** TCP service, port 1337  
**Impact:** Full plaintext recovery of both flags

### Attack Methodology

Because XOR is a symmetric, invertible operation, knowing a portion of the plaintext allows direct key extraction:

```
key[i] = ciphertext[i] XOR plaintext[i]
```

With the flag prefix `THM{` and suffix `}`, all 5 key bytes can be recovered precisely. Early attempts using partial cribs (prefix only) or brute-force tools (CyberChef's XOR brute-force) were insufficient because the key needed to be recovered fresh for each session before the connection timed out or cycled.

#### Failed Approaches

Several scripts were tested during the process. Initial attempts recovered only partial keys, producing incorrect results:

* Scripts relying solely on `THM{` as the crib recovered 4 of 5 key bytes, but the unconstrained fifth byte produced false positives that the server rejected.
* CyberChef's brute-force XOR module was too slow to operate within the session lifecycle.
* Scripts using only printable-ASCII validity as a filter for the fifth byte returned ambiguous candidates.

#### Successful Approach

The decisive insight was to use **both ends of the known plaintext simultaneously** — the prefix `THM{` to derive key bytes 0–3, and the closing `}` to derive key byte 4 using the last ciphertext byte:

```python
def recover_key(hex_encoded):
    cipher = bytes.fromhex(hex_encoded)

    known_prefix = b"THM{"
    known_suffix = b"}"
    key_len = 5

    key = [None] * key_len

    # Recover key bytes 0–3 from the known prefix
    for i in range(len(known_prefix)):
        key[i % key_len] = cipher[i] ^ known_prefix[i]

    # Recover key byte 4 from the known suffix (last byte of ciphertext)
    key[(len(cipher) - 1) % key_len] = cipher[-1] ^ known_suffix[0]

    return ''.join(chr(k) for k in key)

if __name__ == "__main__":
    hex_encoded = input("Cole o texto XOR em hex: ").strip()
    key = recover_key(hex_encoded)
    print("Chave recuperada:", key)
```

#### Execution

The workflow was:

1. Connect to the service and copy the hex ciphertext **without submitting an answer** (to keep the session open).
2. Run the key-recovery script with the copied ciphertext.
3. Submit the recovered key to the service within the same session.

```bash
nc 10.82.139.121 1337
```

```
This XOR encoded text has flag 1: 6d091b030008203a16047c392239044d75351313782f244b11550d2f10254b352f48054b39190a0d
What is the encryption key? 9AVxp
Congrats! That is the correct key! Here is flag 2: THM{...}
```

**Flag 2** was returned directly by the service upon successful key submission.

**Flag 1** was then recovered offline by decrypting the original ciphertext using the recovered key in CyberChef (XOR operation with the known 5-byte key).

---

## 🔓 Privilege Escalation

*Not applicable. This challenge is a standalone cryptographic service with no system access or shell interaction involved.*

---

## 🧠 Lessons Learned

**1. Session lifecycle awareness is critical.**  
The most significant early mistake was recovering a key from one session and submitting it in a different one. Because the ciphertext is regenerated per connection, the key also changes. The solution required completing the entire workflow — capture, analyse, respond — within a single session.

**2. Partial known-plaintext is often enough.**  
The attack required knowing only 5 bytes of plaintext: `THM{` (4 bytes) and `}` (1 byte). This maps exactly to the 5-byte repeating key, enabling complete key reconstruction without brute force. Recognising the flag format as a known-plaintext crib was the core insight.

**3. Repeating-key XOR is fundamentally broken when any plaintext is known.**  
This challenge demonstrates why repeating-key XOR offers no meaningful security. In real-world contexts, predictable output formats (HTTP headers, file magic bytes, protocol headers) serve the same role as the `THM{` prefix, making this class of cipher trivially broken with even minimal known-plaintext.

**4. Iterative debugging under constraints builds intuition.**  
Working through several failing scripts before arriving at the correct approach reinforced understanding of why each method failed — particularly how printable-ASCII validation alone is an insufficient constraint when selecting the unknown key byte.

---

## 🧩 Tools Used

* **Netcat** — TCP service interaction
* **Python 3** — Custom known-plaintext XOR key-recovery script
* **CyberChef** — Offline XOR decryption to recover Flag 1

---

## ⚠️ Notes

* Flags are intentionally omitted from this writeup
* This writeup focuses on methodology, cryptographic reasoning, and the iterative problem-solving process
