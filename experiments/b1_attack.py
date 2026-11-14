"""B1: attribute recovery from the unsalted PQSSI commitment (Eq. (1) of Boi et al.).

C = BLAKE3(canon(claims) || sub || credId || exp || schemaId). Premise of the paper (Sect. 5.1; experiment in Sect. 9.1):
the verifier knows sub, exp, schemaId (JWT payload, Listing 2) and credId. All data are synthetic.
"""
import datetime
import json
import time

import blake3

# Synthetic fixture (not real data).
SUB = b"did:iota:7f6c943e:0x8f4824d45c0285731ece9b8190cf30dc89e8af14ddd8f5665f4e077ec43d95c2"
CRED_ID = b"urn:uuid:3f1c"
EXP = b"1801405572"
SCHEMA = b"https://example.com/schemas/pqzkvc.json"


def canon(claims):
    """Deterministic JSON encoding of the claims (sorted keys, no whitespace)."""
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()


def commit(claims, sub=SUB, cred_id=CRED_ID, exp=EXP, schema=SCHEMA):
    """The PQSSI commitment of Eq. (1); no salt."""
    return blake3.blake3(canon(claims) + sub + cred_id + exp + schema).digest()


def candidates(years, codes):
    """Birth dates over `years` years from 1926-01-01, times ICD-10 codes F30..F3(codes-1)."""
    start = datetime.date(1926, 1, 1)
    for d in range(round(365.25 * years)):
        bd = (start + datetime.timedelta(days=d)).isoformat()
        for i in range(codes):
            yield {"birthDate": bd, "diagnosisCategory": f"F3{i}"}


def recover(target, years, codes):
    """Enumerate candidates until one matches `target`; return (claims or None, tries, seconds)."""
    t0 = time.perf_counter()
    tries = 0
    for c in candidates(years, codes):
        tries += 1
        if commit(c) == target:
            return c, tries, time.perf_counter() - t0
    return None, tries, time.perf_counter() - t0


def hash_rate(samples=200_000):
    """Commitments per second on this machine."""
    t0 = time.perf_counter()
    for i in range(samples):
        commit({"birthDate": "1987-03-14", "diagnosisCategory": f"F3{i % 10}"})
    return samples / (time.perf_counter() - t0)


def run(years=100, codes=10, secret=None, rate_samples=200_000):
    """Run the attack once and return a result dictionary."""
    secret = secret or {"birthDate": "1987-03-14", "diagnosisCategory": "F32"}
    found, tries, secs = recover(commit(secret), years, codes)
    rate = hash_rate(rate_samples)
    space = round(365.25 * years) * codes
    return {
        "fixture": {
            "verifier_visible": {"sub": SUB.decode(), "credId (premise)": CRED_ID.decode(),
                                 "exp": EXP.decode(), "schemaId": SCHEMA.decode()},
            "hidden_claims": sorted(secret),
            "encoding": "compact JSON with sorted keys for the claims, then sub||credId||exp||schemaId",
            "dictionary": f"birth dates on {round(365.25 * years)} consecutive days from 1926-01-01 "
                          f"x ICD-10 codes F30..F3{codes - 1}",
        },
        "candidate_space": space,
        "recovered": found == secret,
        "tries_until_found": tries,
        "seconds_until_found": round(secs, 4),
        "hashes_per_second": round(rate, 1),
        "seconds_full_space_estimate": round(space / rate, 4),
        "seconds_expected_uniform_secret": round(space / 2 / rate, 4),  # half the dictionary on average
    }
