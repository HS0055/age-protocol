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
import base64, hashlib, json, re, sys
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

SURROGATE = re.compile(r"[\ud800-\udfff]")

def json_string(text: str) -> str:
    """JSON string form: two-character escapes, \\u00xx below 0x20, else literal.

    RFC 8785 defers to ECMAScript for strings, and a well-formed
    JSON.stringify escapes an unpaired surrogate as \\udXXX rather than
    emitting it. Python holds code points, so every surrogate in a str is by
    definition unpaired; encoding them raw would produce different canonical
    bytes, a different receipt id, and a different signature input than the
    reference. That is worse than the crash it replaced, because a crash is
    visible and a wrong id is not.
    """
    out = json.dumps(text, ensure_ascii=False)
    return SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group()), out)

# Nesting deeper than this is rejected rather than recursed into: a verifier
# is handed JSON by strangers, and unbounded recursion on attacker-chosen
# nesting is a stack overflow waiting to happen. Nothing honest comes close.
MAX_DEPTH = 64

class TooDeep(ValueError):
    pass

def serialize(value, depth=0) -> str:
    if depth > MAX_DEPTH: raise TooDeep(f"nesting deeper than {MAX_DEPTH} levels")
    if value is None: return "null"
    if value is True: return "true"
    if value is False: return "false"
    if isinstance(value, str): return json_string(value)
    if isinstance(value, (int, float)): return es6_number(value)
    if isinstance(value, (list, tuple)): return "[" + ",".join(serialize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders members by UTF-16 code unit, not by code point, so a
        # supplementary-plane key sorts before U+FFFF: its first code unit is a
        # surrogate at U+D800. Sorting the Python strings themselves would put
        # them the other way round and reproduce neither an id nor a signature.
        # Sorting is by UTF-16 code unit. surrogatepass is right here and only
        # here: these bytes order the members and are never emitted, and an
        # unpaired surrogate in a key would otherwise fail to encode. The key
        # itself still goes through json_string, which escapes it.
        members = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json_string(k) + ":" + serialize(v, depth + 1) for k, v in members) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")

def canonical(value) -> bytes:
    """RFC 8785 JCS: UTF-16 key order, ES6 numbers, no whitespace.

    Unpaired surrogates are escaped by json_string, so nothing here can fail
    to encode.
    """
    return serialize(value).encode("utf-8")

def thumbprint(jwk: dict) -> str:
    """RFC 7638 over the required members only."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64u_encode(hashlib.sha256(canonical(required)).digest())

SIGNATURE = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")

def ed25519_verify(jwk: dict, sig_b64u: str, message: bytes) -> bool:
    # Exactly 86 unpadded base64url characters. Decoding leniently would
    # accept a padded spelling this implementation's counterpart rejects, and
    # two verifiers that disagree about which receipts are valid are worse
    # than one verifier.
    if not isinstance(sig_b64u, str) or not SIGNATURE.match(sig_b64u):
        return False
    if not isinstance(jwk, dict) or not isinstance(jwk.get("x"), str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"])).verify(b64u_decode(sig_b64u), message)
        return True
    except (InvalidSignature, ValueError):
        return False

RECEIPT_ID = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
MAX_SAFE = 9007199254740991

def artifacts_problem(value, member: str):
    if not isinstance(value, list): return f"{member} must be an array"
    for i, item in enumerate(value):
        if not isinstance(item, dict) or not isinstance(item.get("kind"), str) or not isinstance(item.get("digest"), str):
            return f"{member} entry {i} must be an object with a string kind and digest"
    return None

def depth_problem(value, path="", depth=0):
    if depth > MAX_DEPTH:
        return f"{path or 'the core'} is nested deeper than {MAX_DEPTH} levels"
    if isinstance(value, list):
        for i, item in enumerate(value):
            problem = depth_problem(item, f"{path}[{i}]", depth + 1)
            if problem: return problem
    elif isinstance(value, dict):
        for key, item in value.items():
            problem = depth_problem(item, f"{path}.{key}" if path else key, depth + 1)
            if problem: return problem
    return None

def number_problem(value, path=""):
    """A core carries only integers of magnitude at most 2**53 - 1."""
    if isinstance(value, bool): return None
    if isinstance(value, int):
        return None if abs(value) <= MAX_SAFE else f"{path or 'the core'} {value} is outside the safe integer range"
    if isinstance(value, float):
        # RFC 8785 handles numbers as IEEE 754 doubles, so 3.0 and 3 denote the
        # same value and canonicalize to the same bytes. The rule is about the
        # value, not how the literal was spelled.
        if value.is_integer() and abs(value) <= MAX_SAFE: return None
        return f"{path or 'the core'} {value!r} must be an integer of magnitude at most {MAX_SAFE}"
    if isinstance(value, list):
        for i, item in enumerate(value):
            problem = number_problem(item, f"{path}[{i}]")
            if problem: return problem
    elif isinstance(value, dict):
        for key, item in value.items():
            problem = number_problem(item, f"{path}.{key}" if path else key)
            if problem: return problem
    return None

def shape_problem(value):
    """The required members, per the Required members table in README.md.

    Without this a verifier accepts receipts the reference rejects, which is
    the one failure mode an interop claim exists to prevent.
    """
    if not isinstance(value, dict): return "receipt must be an object"
    if value.get("receipt_version") != "0.1":
        return f"receipt_version {value.get('receipt_version')!r} is not 0.1"
    agent = value.get("agent")
    if not isinstance(agent, str) or not agent.startswith("age:agent:") or agent == "age:agent:":
        return "agent must be an age:agent: id"
    if not isinstance(value.get("timestamp"), str): return "timestamp must be a string"
    if not isinstance(value.get("task"), dict): return "task must be an object"
    action = value.get("action")
    if not isinstance(action, dict) or not isinstance(action.get("type"), str):
        return "action must be an object with a string type"
    for member in ("inputs", "outputs"):
        problem = artifacts_problem(value.get(member), member)
        if problem: return problem
    if not isinstance(value.get("environment"), dict): return "environment must be an object"
    # .get() cannot tell an absent member from an explicit null, and the two
    # are different here: policy is required, and may be null only if present.
    if "policy" not in value: return "policy must be an object or null"
    if value["policy"] is not None and not isinstance(value["policy"], dict):
        return "policy must be an object or null"
    if not isinstance(value.get("id"), str) or not RECEIPT_ID.match(value["id"]):
        return "id must be a sha256: digest"
    if not isinstance(value.get("signatures"), list): return "signatures must be an array"
    core = core_of(value)
    return depth_problem(core) or number_problem(core)

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

def json_int(value):
    """A JSON integer within the safe range, or None.

    Three traps, all of which produced real disagreements with the reference:

    Booleans. JSON has no boolean-as-number, but Python evaluates False == 0,
    so an index of false would be read as position 0 and an inclusion proof
    for that position would verify.

    Spelling. RFC 8785 handles numbers as IEEE 754 doubles, so 3.0 and 3 are
    the same number. Rejecting the float type rather than the non-integral
    value disagreed with a reference that only ever sees a double.

    Range. Python integers are arbitrary precision, so 2**60 is a perfectly
    good int here while the reference rejects it as beyond the safe range.
    Accepting it would verify a root the reference refuses, which is a false
    positive on this side.

    Every integer read out of untrusted JSON goes through here.
    """
    if isinstance(value, bool): return None
    if isinstance(value, float):
        if not value.is_integer(): return None
        value = int(value)
    if not isinstance(value, int): return None
    if abs(value) > MAX_SAFE: return None
    return value

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")

def verify_inclusion(leaf: bytes, proof: dict, root_hex: str) -> bool:
    """RFC 9162 section 2.1.3.2. Answers for any input rather than raising."""
    if not isinstance(proof, dict) or not isinstance(root_hex, str): return False
    fn, size = json_int(proof.get("index")), json_int(proof.get("size"))
    if fn is None or size is None or size < 1: return False
    path = proof.get("path")
    if not isinstance(path, list): return False
    sn = size - 1
    if not (0 <= fn < size): return False
    r = leaf_hash(leaf)
    for entry in path:
        if sn == 0: return False
        if not isinstance(entry, str) or not HEX64.match(entry): return False
        p = bytes.fromhex(entry)
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r.hex() == root_hex.lower()

def embedded_key_problem(value):
    """The embedded agent key carries exactly kty, crv and x, and nothing else.

    It sits outside the core, so two receipts whose keys differ share one id,
    and a proof is matched by id while a leaf is the whole receipt.
    """
    if not isinstance(value, dict): return "agent signature carries no public key"
    if not all(isinstance(value.get(m), str) for m in ("kty", "crv", "x")):
        return "agent signature carries no public key"
    if sorted(value) != ["crv", "kty", "x"]:
        return "embedded agent key must carry exactly crv, kty, and x, not " + ", ".join(sorted(value))
    if value["kty"] != "OKP": return f'embedded agent key kty {value["kty"]!r} is not OKP'
    if value["crv"] != "Ed25519": return f'embedded agent key crv {value["crv"]!r} is not Ed25519'
    return None

def root_verdict(receipt, root_doc, proof, registry_jwks):
    """Whether this receipt is in this signed root, answering for any input.

    Both halves are required: a tree nobody has checked the signature of
    proves nothing, and a signature over a tree the receipt is not in proves
    nothing either.
    """
    if not isinstance(root_doc, dict) or not isinstance(proof, dict):
        return False, "root document or proof is not an object"
    detail = f'{root_doc.get("date")} sequence {root_doc.get("sequence_start")} to {root_doc.get("sequence_end")}'
    registry = root_doc.get("registry")
    root = root_doc.get("root")
    start, end = json_int(root_doc.get("sequence_start")), json_int(root_doc.get("sequence_end"))
    if (root_doc.get("root_version") != "0.1" or not isinstance(registry, str)
            or not registry.startswith("age:registry:") or not isinstance(root, str)
            or not root.startswith("sha256:") or start is None or end is None
            or start < 1 or end < start):
        return False, detail

    keys = {thumbprint(k): k for k in registry_jwks}
    rkey = keys.get(registry.removeprefix("age:registry:"))
    unsigned = {k: v for k, v in root_doc.items() if k != "signature"}
    if rkey is None or not ed25519_verify(rkey, root_doc.get("signature"), canonical(unsigned)):
        return False, detail

    # The receipt has to be registered by the registry this document names,
    # and the proof has to sit where that registration says it does.
    entry = next((e for e in receipt.get("signatures", [])
                  if isinstance(e, dict) and e.get("role") == "registry" and e.get("signer") == registry), None)
    sequence = json_int(proof.get("sequence"))
    if entry is None or sequence is None or json_int(entry.get("sequence")) != sequence:
        return False, detail
    if json_int(proof.get("size")) != end - start + 1: return False, detail
    if json_int(proof.get("index")) != sequence - start: return False, detail
    return verify_inclusion(canonical(receipt), proof, root.removeprefix("sha256:")), detail

def verify(receipt: dict, registry_jwks: list, root_doc=None, proof=None):
    checks = []
    def rep(name, ok, detail): checks.append((name, ok, detail))

    # 1. Receipt integrity. The shape comes first: ok must never mean less
    # than structurally conformant, or this verifier accepts what the
    # reference rejects.
    problem = shape_problem(receipt)
    if problem is not None:
        rep("Receipt integrity", False, problem)
        rep("Agent signature", False, "not checked, the receipt is malformed")
        rep("Agent identity", False, "not checked, the receipt is malformed")
        return checks

    recomputed = "sha256:" + hashlib.sha256(canonical(core_of(receipt))).hexdigest()
    rep("Receipt integrity", receipt.get("id") == recomputed, receipt.get("id", "<missing>"))

    # Every entry is judged or reported. Taking the first entry of a role and
    # ignoring the rest is what let a forged second registry entry ride along
    # invisibly; order carries no meaning and nothing signs the array.
    entries = receipt["signatures"]
    agents = [e for e in entries if isinstance(e, dict) and e.get("role") == "agent"]

    # 2 and 3. Exactly one agent entry, its key, and its identity.
    if len(agents) != 1:
        detail = "no agent signature" if not agents else f"{len(agents)} agent signatures, exactly one is required"
        rep("Agent signature", False, detail); rep("Agent identity", False, detail)
    else:
        agent_sig = agents[0]
        key_problem = embedded_key_problem(agent_sig.get("key"))
        if key_problem is not None:
            rep("Agent signature", False, key_problem); rep("Agent identity", False, key_problem)
        elif agent_sig.get("alg") != "Ed25519":
            detail = f'alg {agent_sig.get("alg")!r} is not Ed25519'
            rep("Agent signature", False, detail); rep("Agent identity", False, detail)
        else:
            rep("Agent signature",
                ed25519_verify(agent_sig["key"], agent_sig.get("signature"), canonical(core_of(receipt))),
                str(agent_sig.get("signer")))
            derived = "age:agent:" + thumbprint(agent_sig["key"])
            rep("Agent identity", derived == agent_sig.get("signer") == receipt["agent"],
                "key thumbprint matches id" if derived == receipt["agent"] else f"derived {derived}")

    # 4. Every registry entry, each reported by position when there is more
    # than one, and every one of them must verify.
    keys = {thumbprint(k): k for k in registry_jwks}
    registries = [e for e in entries if isinstance(e, dict) and e.get("role") == "registry"]
    if not registries:
        rep("Registry signature", None, "absent, unregistered receipt")
    for i, reg in enumerate(registries, start=1):
        name = "Registry signature" if len(registries) == 1 else f"Registry signature {i}"
        signer = reg.get("signer")
        if not isinstance(signer, str) or not signer.startswith("age:registry:"):
            rep(name, False, f"signer {signer!r} is not an age:registry: id"); continue
        if reg.get("alg") != "Ed25519":
            rep(name, False, f'alg {reg.get("alg")!r} is not Ed25519'); continue
        sequence = reg.get("sequence")
        if (not isinstance(sequence, int) or isinstance(sequence, bool)
                or sequence < 1 or sequence > MAX_SAFE):
            rep(name, False, f"sequence {sequence!r} is not a positive integer no greater than {MAX_SAFE}")
            continue
        if not isinstance(reg.get("registered_at"), str):
            rep(name, False, "registered_at must be a string"); continue
        key = keys.get(signer.removeprefix("age:registry:"))
        if not key:
            rep(name, False, f"registry key {signer} not available"); continue
        attestation = {"attestation_version": "0.1", "receipt": receipt["id"], "agent": receipt["agent"],
                       "sequence": reg["sequence"], "registered_at": reg["registered_at"], "registry": signer}
        rep(name, ed25519_verify(key, reg.get("signature"), canonical(attestation)),
            f'{signer}  sequence #{reg["sequence"]}')

    # Roles this version does not know are carried and reported, never judged,
    # so runtime, hardware and organization signers can be added later.
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            rep(f"signature entry {i}", False, f"entry {i} is not an object"); continue
        role = entry.get("role")
        if role in ("agent", "registry"): continue
        if not isinstance(role, str):
            # Not a signature at all. Skipping it would let arbitrary content
            # ride inside the array unreported. An empty string IS a string,
            # and so is an unknown role rather than a malformed entry.
            rep(f"signature entry {i}", False, f"role {role!r} is not a string")
            continue
        safe = "".join(c for c in role if c.isalnum() or c in "_-")[:32]
        rep(f"{safe or 'unknown'} signature", None, f"unknown role {role[:40]}, not checked")

    # 5. Commit binding
    act = receipt.get("action") if isinstance(receipt.get("action"), dict) else {}
    if act.get("type") != "git.commit":
        rep("Commit binding", None, f'action {act.get("type")} is not a commit')
    else:
        commit = act.get("commit")
        if not isinstance(commit, str) or not COMMIT.match(commit):
            rep("Commit binding", False, f"commit {commit!r} is not a 40 character hex id")
        else:
            outputs = receipt.get("outputs") if isinstance(receipt.get("outputs"), list) else []
            listed = any(isinstance(o, dict) and o.get("kind") == "commit" and o.get("ref") == commit
                         for o in outputs)
            rep("Commit binding", listed,
                f'{commit[:7]} ({act.get("files_changed")} files)' if listed
                else f"{commit[:7]} is not listed in outputs")

    # 6. Root inclusion
    if root_doc is not None and proof is not None:
        rep("Root inclusion", *root_verdict(receipt, root_doc, proof, registry_jwks))

    return checks

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--no-root"]
    # A Merkle leaf is the whole receipt, so any change to the signature array
    # puts the receipt outside the published root even when the receipt itself
    # is fine. --no-root asks only "is this receipt valid", which is the
    # question to ask when comparing two implementations entry by entry.
    skip_root = "--no-root" in sys.argv
    g = json.load(open(args[0]))
    keys, root_doc = [g["keys"]["registry_public"]], (None if skip_root else g["root"]["document"])
    sys.argv = [sys.argv[0], *args]
    if len(sys.argv) > 2:
        given = json.loads(sys.argv[2])
        # Only a proof that belongs to this receipt is worth applying. Falling
        # back to another receipt's proof would report a root-inclusion
        # failure that says nothing about the receipt in hand, and would hide
        # whatever the other checks found.
        given_id = given.get("id") if isinstance(given, dict) else None
        proof = next((i["proof"] for i in g["receipts"] if i["receipt"].get("id") == given_id), None)
        items = [{"receipt": given, "proof": proof}]
    else:
        items = g["receipts"]
    failed = False
    for item in items:
        receipt = item["receipt"]
        print(receipt.get("id", "<no id>") if isinstance(receipt, dict) else "<not a receipt>")
        # The specification requires a verdict for any input, including input
        # that is not a receipt at all. An exception is not a verdict.
        try:
            results = verify(receipt, keys, root_doc, item["proof"])
        except Exception as error:                                  # noqa: BLE001
            results = [("Receipt integrity", False, f"{type(error).__name__}: {error}")]
        for name, ok, detail in results:
            mark = "-" if ok is None else ("PASS" if ok else "FAIL")
            if ok is False: failed = True
            print(f"  [{mark:>4}] {name:<20} {detail}")
    print("  VERIFIED" if not failed else "  FAILED")
    sys.exit(1 if failed else 0)
