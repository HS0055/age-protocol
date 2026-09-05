"""A second, independent implementation of AGE Protocol v0.1 verification.

This file exists to be checked, not trusted. It shares no code with
@ageprotocol/receipts: a different language, a different crypto library, and
its own canonicalizer written from the specification in README.md beside this
file. It agrees with the reference implementation on every value of
golden-v0.1.json, which is what makes the format interoperable rather than
merely documented.

Read it. It is about two hundred lines, and it is the whole of what verifying
an AGE receipt requires. If AGE disappeared tomorrow, this file and a receipt
would still be enough.

    python3 verify.py golden-v0.1.json              # verify every receipt in the vector
    python3 verify.py golden-v0.1.json "$(cat r.json)"   # verify one receipt

Exit status is 0 when everything verified and 1 when anything failed. The one
dependency is `cryptography`, for Ed25519; the Python standard library has no
Ed25519 implementation.
"""
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def shortest_decimal(number: float):
    """Shortest round-trip digits s and exponent n, with number == 0.s * 10**n."""
    mantissa, _, exponent_text = repr(number).partition("e")
    exponent = int(exponent_text) if exponent_text else 0
    whole, _, fraction = mantissa.partition(".")
    all_digits = whole + fraction
    stripped = all_digits.lstrip("0")
    n = len(whole) - (len(all_digits) - len(stripped)) + exponent
    return (stripped.rstrip("0") or "0"), n

def es6_number(value) -> str:
    """ECMAScript Number::toString, which RFC 8785 requires for every JSON number.

    Every JSON number is a double, so an integral one has no fractional part
    (1, never 1.0) and one past 1e21 is exponential (1e+21, never the digits).
    """
    try:
        number = float(value)
    except OverflowError:
        raise ValueError("number is out of range for a JSON double")
    if number != number or number in (float("inf"), float("-inf")):
        raise ValueError("a non-finite number cannot be represented in JSON")
    if number == 0: return "0"
    if number < 0: return "-" + es6_number(-number)
    digits, n = shortest_decimal(number)
    k = len(digits)
    if k <= n <= 21: return digits + "0" * (n - k)
    if 0 < n <= 21: return digits[:n] + "." + digits[n:]
    if -6 < n <= 0: return "0." + "0" * -n + digits
    exponent = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"

def json_string(text: str) -> str:
    """JSON string form: the two-character escapes, \\u00xx below 0x20, else literal."""
    return json.dumps(text, ensure_ascii=False)

def serialize(value) -> str:
    if value is None: return "null"
    if value is True: return "true"
    if value is False: return "false"
    if isinstance(value, str): return json_string(value)
    if isinstance(value, (int, float)): return es6_number(value)
    if isinstance(value, (list, tuple)): return "[" + ",".join(serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders members by UTF-16 code unit, not by code point, so a
        # supplementary-plane key sorts before U+FFFF: its first code unit is a
        # surrogate at U+D800. Sorting the Python strings themselves would put
        # them the other way round and reproduce neither an id nor a signature.
        members = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(json_string(k) + ":" + serialize(v) for k, v in members) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")

def canonical(value) -> bytes:
    """RFC 8785 JCS: UTF-16 key order, ES6 numbers, no whitespace."""
    return serialize(value).encode("utf-8")

def thumbprint(jwk: dict) -> str:
    """RFC 7638 over the required members only."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64u_encode(hashlib.sha256(canonical(required)).digest())

def ed25519_verify(jwk: dict, sig_b64u: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"])).verify(b64u_decode(sig_b64u), message)
        return True
    except (InvalidSignature, ValueError):
        return False

def core_of(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k not in ("id", "signatures")}

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()

def node_hash(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()

def split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def merkle_root(leaves):
    if not leaves: return hashlib.sha256(b"").digest()
    if len(leaves) == 1: return leaf_hash(leaves[0])
    k = split_point(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))

def verify_inclusion(leaf: bytes, proof: dict, root_hex: str) -> bool:
    """RFC 9162 section 2.1.3.2."""
    fn, sn = proof["index"], proof["size"] - 1
    if not (0 <= fn < proof["size"]): return False
    r = leaf_hash(leaf)
    for entry in proof["path"]:
        if sn == 0: return False
        p = bytes.fromhex(entry)
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r.hex() == root_hex.lower()

def verify(receipt: dict, registry_jwks: list, root_doc=None, proof=None):
    checks = []
    def rep(name, ok, detail): checks.append((name, ok, detail))

    # 1. Receipt integrity
    recomputed = "sha256:" + hashlib.sha256(canonical(core_of(receipt))).hexdigest()
    rep("Receipt integrity", receipt.get("receipt_version") == "0.1" and receipt.get("id") == recomputed,
        receipt.get("id", "<missing>"))

    agent_sig = next((s for s in receipt["signatures"] if s["role"] == "agent"), None)
    if not agent_sig:
        rep("Agent signature", False, "absent"); rep("Agent identity", False, "absent")
    else:
        # 2. Agent signature over the canonical core
        rep("Agent signature", ed25519_verify(agent_sig["key"], agent_sig["signature"], canonical(core_of(receipt))),
            agent_sig["signer"])
        # 3. Agent identity: key thumbprint must give both signer and agent
        derived = "age:agent:" + thumbprint(agent_sig["key"])
        rep("Agent identity", derived == agent_sig["signer"] == receipt["agent"],
            "key thumbprint matches id" if derived == receipt["agent"] else f"derived {derived}")

    # 4. Registry signature over the attestation
    reg = next((s for s in receipt["signatures"] if s["role"] == "registry"), None)
    if not reg:
        rep("Registry signature", None, "absent, unregistered receipt")
    else:
        keys = {thumbprint(k): k for k in registry_jwks}
        key = keys.get(reg["signer"].removeprefix("age:registry:"))
        if not key:
            rep("Registry signature", False, "registry key not available")
        else:
            attestation = {"attestation_version": "0.1", "receipt": receipt["id"], "agent": receipt["agent"],
                           "sequence": reg["sequence"], "registered_at": reg["registered_at"], "registry": reg["signer"]}
            rep("Registry signature", ed25519_verify(key, reg["signature"], canonical(attestation)),
                f'{reg["signer"]}  sequence #{reg["sequence"]}')

    # 5. Commit binding
    act = receipt.get("action", {})
    if act.get("type") != "git.commit":
        rep("Commit binding", None, f'action {act.get("type")} is not a commit')
    else:
        c = act.get("commit", "")
        listed = any(o.get("kind") == "commit" and o.get("ref") == c for o in receipt.get("outputs", []))
        ok = len(c) == 40 and all(ch in "0123456789abcdef" for ch in c) and listed
        rep("Commit binding", ok, f'{c[:7]} ({act.get("files_changed")} files)')

    # 6. Root inclusion
    if root_doc and proof:
        keys = {thumbprint(k): k for k in registry_jwks}
        rkey = keys.get(root_doc["registry"].removeprefix("age:registry:"))
        unsigned = {k: v for k, v in root_doc.items() if k != "signature"}
        sig_ok = rkey is not None and root_doc.get("root_version") == "0.1" and \
                 ed25519_verify(rkey, root_doc["signature"], canonical(unsigned))
        size = root_doc["sequence_end"] - root_doc["sequence_start"] + 1
        inc = sig_ok and proof["size"] == size and \
              proof["index"] == proof["sequence"] - root_doc["sequence_start"] and \
              verify_inclusion(canonical(receipt), proof, root_doc["root"].removeprefix("sha256:"))
        rep("Root inclusion", inc, f'{root_doc["date"]} sequence {root_doc["sequence_start"]} to {root_doc["sequence_end"]}')

    return checks

if __name__ == "__main__":
    g = json.load(open(sys.argv[1]))
    keys, root_doc = [g["keys"]["registry_public"]], g["root"]["document"]
    if len(sys.argv) > 2:
        given = json.loads(sys.argv[2])
        proof = next((i["proof"] for i in g["receipts"] if i["receipt"].get("id") == given.get("id")),
                     g["receipts"][0]["proof"])
        items = [{"receipt": given, "proof": proof}]
    else:
        items = g["receipts"]
    failed = False
    for item in items:
        print(f'{item["receipt"].get("id", "<no id>")}')
        for name, ok, detail in verify(item["receipt"], keys, root_doc, item["proof"]):
            mark = "-" if ok is None else ("PASS" if ok else "FAIL")
            if ok is False: failed = True
            print(f"  [{mark:>4}] {name:<20} {detail}")
    print("  VERIFIED" if not failed else "  FAILED")
    sys.exit(1 if failed else 0)
