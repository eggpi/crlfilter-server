#!/usr/bin/env python

import math
import struct
import hashlib
import cPickle as pickle

import bitarray
import pyasn1.codec.der.decoder as der_decoder

ISSUER_HASH_FMT = "20s" # 20-byte string
ISSUER_FILTER_LENGTH_FMT = "i" # 4-byte integer
ISSUER_FILTER_NENTRIES_FMT = "i" # 4-byte integer

FILTER_VERSION_FMT = "i" # 4-byte integer
FILTER_LOGP_FMT = "b" # 1-byte integer

COMMON_NAME_OID = (2, 5, 4, 3)
ORG_NAME_OID = (2, 5, 4, 10)
ORG_UNIT_NAME_OID = (2, 5, 4, 11)

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
        self.entries = crl
        self.logp = logp
        self.issuer = self.hash_issuer_fields(issuer)

    def tobytes(self):
        entries = gcs_encode(self.entries, self.logp).tobytes()
        result = struct.pack(
            "=" + ISSUER_HASH_FMT + ISSUER_FILTER_NENTRIES_FMT +
            ISSUER_FILTER_LENGTH_FMT, self.issuer, len(self.entries),
            len(entries))
        result += entries

        return result

    def hash_issuer_fields(self, issuerDER):
        decoded, _ = der_decoder.decode(issuerDER)

        # get the first value for each field, this seems to be what
        # Necko does when parsing certs
        common_name, org_name, org_unit_name = None, None, None
        for component in decoded:
            for element in component:
                oid = element[0].asTuple()
                if oid == COMMON_NAME_OID and common_name is None:
                    common_name = str(element[1])
                elif oid == ORG_NAME_OID and org_name is None:
                    org_name = str(element[1])
                elif oid == ORG_UNIT_NAME_OID and org_unit_name is None:
                    org_unit_name = str(element[1])

        # normalize missing values to ''
        common_name = common_name if common_name is not None else ''
        org_name = org_name if org_name is not None else ''
        org_unit_name = org_unit_name if org_unit_name is not None else ''

        issuer = common_name + org_name + org_unit_name
        return hashlib.sha1(issuer).digest()

def bits(n):
    return int(math.ceil(math.log(n) / math.log(2))) if n else 0

def unary_encode(n):
    unary = bitarray.bitarray(n + 1)
    unary[:-1], unary[-1] = 0, 1
    return unary

def binary_encode(n, nbits):
    return bitarray.bitarray(bin((1 << nbits) + n)[3:])

def hash_and_truncate(n, nbits):
    # convert n into a string of octets separated by :
    hn = hex(long(n))[2:-1].upper()
    n = ':'.join(hn[i] + hn[i+1] for i in range(0, len(hn) - 1, 2))
    hash_as_hex = hashlib.sha1(n).hexdigest()

    # FIXME what happens when nbits isn't divisible by 4?
    # should be fine anyway, right?
    return int(hash_as_hex[-nbits / 4:], 16)

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
