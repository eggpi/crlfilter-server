#!/usr/bin/env python

import math
import struct
import hashlib
import cPickle as pickle

import bitarray

ISSUER_NAME_FMT = "20s" # 20-byte string
ISSUER_FILTER_LENGTH_FMT = "i" # 4-byte integer

FILTER_VERSION_FMT = "i" # 4-byte integer
FILTER_LOGP_FMT = "b" # 1-byte integer

class CRLFilter(object):
    def __init__(self, version, logp, issuers):
        self.version = version
        self.logp = logp
        self.issuers = issuers

    def tobytes(self):
        result = struct.pack(
            "=" + FILTER_VERSION_FMT + FILTER_LOGP_FMT,
            self.version, self.logp)

        for issuer in self.issuers:
            result += issuer.tobytes()

        return result

class IssuerCRLFilter(object):
    def __init__(self, issuer, crl, logp):
        self.issuer = issuer
        self.entries = crl
        self.logp = logp

    def tobytes(self):
        entries = gcs_encode(self.entries, self.logp).tobytes()
        result = struct.pack(
            "=" + ISSUER_NAME_FMT + ISSUER_FILTER_LENGTH_FMT,
            self.issuer, len(entries))
        result += entries

        return result

def bits(n):
    return int(math.ceil(math.log(n) / math.log(2))) if n else 0

def unary_encode(n):
    unary = bitarray.bitarray(n + 1)
    unary[:-1], unary[-1] = 0, 1
    return unary

def binary_encode(n, nbits):
    return bitarray.bitarray((n >> i) % 2 for i in range(nbits))

def hash_and_truncate(n, nbits):
    n = hex(n)[2:]
    hash_as_int = int(hashlib.sha1(n).hexdigest(), 16)
    return hash_as_int % (1 << nbits)

def golomb_encode(n, logp):
    p = (1 << logp)
    q = n // p
    r = n % p
    return unary_encode(q) + binary_encode(r, logp)

def gcs_encode(items, logp):
    hash_bits = bits(len(items)) + logp
    hashes = [0] + sorted(hash_and_truncate(item, hash_bits) for item in items)

    result = bitarray.bitarray()
    for i in range(1, len(hashes)):
        result += golomb_encode(hashes[i] - hashes[i-1], logp)

    return result

def diff_crlfilters(filter1, filter2):
    issuers1, issuers2 = filter1.issuers, filter2.issuers
    entries1, entries2 = set(issuers1.entries), set(issuers2.entries)
    return list(entries2 - entries1), list(entries1 - entries2)

def build_crlfilter(version, logp, crls):
    entries = []
    for issuer, crl in crls:
        entries.append(IssuerCRLFilter(issuer, crl, logp))
    return CRLFilter(version, logp, entries)

def build_crlfilter_from_crlcache(crlcache_path, version, logp):
    with open(crlcache_path) as crlcache_file:
        crlcache = pickle.load(crlcache_file)

    issuers_and_certs = (
        (crl["issuer"], crl["revokedCertificates"]) for crl in crlcache)
    return build_crlfilter(version, logp, issuers_and_certs)
