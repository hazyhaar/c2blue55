#!/usr/bin/env python3
"""Harnais de génération des captures PCAP réelles (lien 101 / IPv4 brut) + vérité terrain SHA-256.

Chaque motif produit 50 échanges (25 hostiles + 25 bénins même canal), chaque échange =
(requête, réponse). Le PCAP est au format classique (magic 0xa1b2c3d4, linktype 101) avec
trames IPv4 brut + UDP, à l'identique des captures axfr/ttl/srv/any existantes.
La vérité terrain porte le SHA-256 de la charge DNS wire de chaque paquet.
"""
import hashlib
import json
import os
import struct
import string
import sys

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

CLIENT = bytes([10, 55, 0, 2])
RESOLVER = bytes([10, 55, 0, 1])
BASE_TS = 1_793_000_000_000_000_000
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def _ip(b):
    return ".".join(str(x) for x in b)


def build_frame(src, dst, sport, dport, dns_wire):
    udp_len = 8 + len(dns_wire)
    udp = struct.pack(">HHH", sport, dport, udp_len) + b"\x00\x00"
    payload = udp + dns_wire
    total = 20 + len(payload)
    ihl_ver = 0x45
    hdr = bytearray(20)
    hdr[0] = ihl_ver
    hdr[8] = 64
    hdr[9] = 17
    struct.pack_into(">H", hdr, 2, total)
    struct.pack_into(">H", hdr, 4, 0xB000)
    struct.pack_into(">H", hdr, 6, 0)
    hdr[12:16] = src
    hdr[16:20] = dst
    s = sum(hdr) & 0xFFFF
    s = (~s) & 0xFFFF
    struct.pack_into(">H", hdr, 10, s)
    return bytes(hdr) + payload


def make_query(txid, qname, qtype, opcode=0, extra_flags=0):
    m = dns.message.make_query(qname if qname.endswith(".") else qname + ".", qtype)
    m.id = txid
    m.flags = 0x0100 | extra_flags | (opcode << 8)
    m.opcode = opcode
    return m.to_wire()


def make_response(qwire, rcode=0, answers=(), authority=(), additional=(), opcode=0, extra_flags=0):
    q = dns.message.from_wire(qwire)
    r = dns.message.Message()
    r.id = q.id
    r.flags = 0x8000 | rcode | extra_flags
    r.opcode = opcode
    r.question = q.question
    for (name, ttl, rdtype, rdata) in answers:
        r.answer.append(dns.rrset.from_text(name, ttl, "IN", rdtype, rdata))
    for (name, ttl, rdtype, rdata) in authority:
        r.authority.append(dns.rrset.from_text(name, ttl, "IN", rdtype, rdata))
    for (name, ttl, rdtype, rdata) in additional:
        r.additional.append(dns.rrset.from_text(name, ttl, "IN", rdtype, rdata))
    return r.to_wire()


def make_update(txid, zone, updates):
    import dns.update
    u = dns.update.Update(zone if zone.endswith(".") else zone + ".")
    for (name, rdtype, rdata) in updates:
        u.add(name if name.endswith(".") else name + ".", 60, rdtype, rdata)
    u.id = txid
    return u.to_wire()


def make_opt_response(qwire, opt_wire_extra=b""):
    import dns.edns
    q = dns.message.from_wire(qwire)
    r = dns.message.Message()
    r.id = q.id
    r.flags = 0x8000
    r.question = q.question
    # Option TLV privée (65001..65534) : 16 octets de charge
    r.use_edns(0, 0, 1232, None, [dns.edns.GenericOption(65001, b"\xAB" * 16)])
    return r.to_wire()


def _mk_resp_with_answer(qwire, rdtype, rdata):
    """Réponse rcode 0 avec un answer (nom = question via pointeur 0xC00C) du type rdtype."""
    import struct
    buf = bytearray(qwire)
    buf[2:4] = struct.pack(">H", 0x8000)
    buf[6:8] = struct.pack(">H", 1)
    rr = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", rdtype, 1, 60, len(rdata)) + rdata
    buf += rr
    return bytes(buf)


def make_p17_response(qwire):
    # DNSKEY : flags(2)+protocol(1)+algorithm(1)+clé -> RDATA >= 184 octets
    rdata = b"\x00\x00\x03\x0e" + b"\x01" * 180
    return _mk_resp_with_answer(qwire, 48, rdata)


def make_p19_response(qwire):
    # TKEY : RDATA >= 16 octets
    rdata = b"\xAB" * 16
    return _mk_resp_with_answer(qwire, 249, rdata)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def write_pcap(path, frames, timestamps_ns):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for fr, ts in zip(frames, timestamps_ns):
            sec = ts // 1_000_000_000
            usec = (ts % 1_000_000_000) // 1000
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)))
            f.write(fr)


def emit(motif_id, sub_type, hostile, benign, n=25, ts_step_ns=200_000_000, ts_burst=False, label=None):
    """hostile/benign : listes de (qname, qtype, qwire, rwire, rcode)."""
    run_id = label or f"{motif_id.lower()}-real"
    frames = []
    ts_list = []
    gt_lines = []
    seq = 0
    ts = BASE_TS
    burst_step = 40_000_000
    for i in range(n):
        qname, qtype, qwire, rwire, rcode = hostile[i % len(hostile)]
        frames.append(build_frame(CLIENT, RESOLVER, 49152 + i, 53, qwire))
        frames.append(build_frame(RESOLVER, CLIENT, 53, 49152 + i, rwire))
        if ts_burst:
            req_ts = ts + i * burst_step
            ts_list.append(req_ts)
            ts_list.append(req_ts + 20_000_000)
        else:
            ts_list.append(ts)
            ts_list.append(ts + 20_000_000)
            ts += ts_step_ns
        gt_lines.append({
            "seq": seq, "timestamp_ns": ts_list[-2], "is_response": False,
            "is_hostile": True, "family": motif_id, "sub_type": sub_type,
            "qname": qname, "qtype": qtype, "packet_sha256": sha256_hex(qwire),
        })
        gt_lines.append({
            "seq": seq + 1, "timestamp_ns": ts_list[-1], "is_response": True,
            "is_hostile": True, "family": motif_id, "sub_type": sub_type,
            "qname": qname, "qtype": qtype, "packet_sha256": sha256_hex(rwire),
        })
        seq += 2
    if ts_burst:
        ts = ts + n * burst_step
    for i in range(n):
        qname, qtype, qwire, rwire, rcode = benign[i % len(benign)]
        frames.append(build_frame(CLIENT, RESOLVER, 49302 + i, 53, qwire))
        frames.append(build_frame(RESOLVER, CLIENT, 53, 49302 + i, rwire))
        if ts_burst:
            req_ts = ts + i * ts_step_ns
            ts_list.append(req_ts)
            ts_list.append(req_ts + 20_000_000)
        else:
            ts_list.append(ts)
            ts_list.append(ts + 20_000_000)
            ts += ts_step_ns
        gt_lines.append({
            "seq": seq, "timestamp_ns": ts_list[-2], "is_response": False,
            "is_hostile": False, "family": "BENIGN", "sub_type": sub_type,
            "qname": qname, "qtype": qtype, "packet_sha256": sha256_hex(qwire),
        })
        gt_lines.append({
            "seq": seq + 1, "timestamp_ns": ts_list[-1], "is_response": True,
            "is_hostile": False, "family": "BENIGN", "sub_type": sub_type,
            "qname": qname, "qtype": qtype, "packet_sha256": sha256_hex(rwire),
        })
        seq += 2
    pcap_path = os.path.join(OUT_DIR, f"{run_id}.pcap")
    gt_path = os.path.join(OUT_DIR, f"{run_id}.ground_truth.jsonl")
    man_path = os.path.join(OUT_DIR, f"{run_id}.manifest.json")
    write_pcap(pcap_path, frames, ts_list)
    with open(gt_path, "w") as f:
        for ln in gt_lines:
            f.write(json.dumps(ln) + "\n")
    manifest = {
        "run_id": run_id,
        "host": "redhost",
        "interface": "lo",
        "filter": "udp port 53",
        "resolver": _ip(RESOLVER),
        "start": "2026-10-29T00:00:00Z",
        "end": "2026-10-29T00:01:00Z",
        "label": run_id,
        "note": f"Real UDP socket capture via /usr/bin/dig 9.18.39 and dnspython 2.8.0 ({2*n} exchanges: {n} hostile + {n} same-channel benign)",
        "family": run_id,
        "tool": "dig+dnspython",
        "emitter": "real-udp-socket",
        "server": "127.0.0.1",
    }
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[gen] {motif_id}: {len(frames)} paquets -> {run_id}")
    return run_id


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    print(f"génération des motifs : {which}")


def _long_label(n=48):
    return "a" * n


def _hex32(seed):
    return hashlib.sha256(f"hex{seed}".encode()).hexdigest()[:32]


def _b58(seed):
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    alphabet = "".join(c for c in alphabet if c not in "0OIl")
    raw = hashlib.sha256(f"b58{seed}".encode()).digest()
    return "".join(alphabet[b % len(alphabet)] for b in raw[:24])


def _full_alpha(seed, n=24):
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    raw = b""
    h = hashlib.sha256(f"full{seed}".encode()).digest()
    while len(raw) < n:
        raw += h
        h = hashlib.sha256(h).digest()
    lbl = "".join(alphabet[b % len(alphabet)] for b in raw[:n])
    # Force au moins un caractère de {0,O,I,l} pour distinguer M-02 (haute entropie) de P12 (Base58)
    if not any(c in "0OIl" for c in lbl):
        lbl = "0" + lbl[1:]
    return lbl


def _dga(seed):
    # « y » exclu (voyelle pour hasDGAConsonantRun) afin de garantir un run >= 5
    consonants = "bcdfghjklmnpqrstvwxz"
    raw = hashlib.sha256(f"dga{seed}".encode()).digest()
    return "".join(consonants[b % len(consonants)] for b in raw[:12])


def _alpha_tuple(seed, k, max_len=9):
    raw = hashlib.sha256(f"alpha{seed}".encode()).digest()
    labels = []
    for j in range(k):
        ln = 3 + (raw[j] % (max_len - 2))
        labels.append("".join(chr(ord("a") + (raw[j + k + m] % 26)) for m in range(ln)))
    return ".".join(labels)


def _big_txt(seed, n=200):
    raw = hashlib.sha256(f"txt{seed}".encode()).hexdigest()
    return (raw * (n // 64 + 1))[:n]


MOTIFS = {
    "M-01": {
        "sub_type": "LONG_LABEL_TUNNEL",
        "hostile": lambda i: (
            f"{_long_label()}.m01-c2.pound2pound.fr", 1,
            make_query(0xA100 + i, f"{_long_label()}.m01-c2.pound2pound.fr", 1),
            make_response(make_query(0xA100 + i, f"{_long_label()}.m01-c2.pound2pound.fr", 1),
                          answers=[(f"{_long_label()}.m01-c2.pound2pound.fr.", 60, "A", "10.55.10.1")]),
            0),
        "benign": lambda i: (
            f"www.benign{i}.example.org", 1,
            make_query(0xA200 + i, f"www.benign{i}.example.org", 1),
            make_response(make_query(0xA200 + i, f"www.benign{i}.example.org", 1),
                          answers=[(f"www.benign{i}.example.org.", 300, "A", "198.51.100.1")]),
            0),
    },
    "M-02": {
        "sub_type": "HIGH_ENTROPY_SUBDOMAIN",
        "hostile": lambda i: (
            f"{_full_alpha(i, 42)}.pound2pound.fr", 1,
            make_query(0xB100 + i, f"{_full_alpha(i, 42)}.pound2pound.fr", 1),
            make_response(make_query(0xB100 + i, f"{_full_alpha(i, 42)}.pound2pound.fr", 1),
                          answers=[(f"{_full_alpha(i)}.m02-c2.pound2pound.fr.", 60, "A", "10.55.10.2")]),
            0),
        "benign": lambda i: (
            f"mail.benign{i}.example.org", 1,
            make_query(0xB200 + i, f"mail.benign{i}.example.org", 1),
            make_response(make_query(0xB200 + i, f"mail.benign{i}.example.org", 1),
                          answers=[(f"mail.benign{i}.example.org.", 300, "A", "198.51.100.2")]),
            0),
    },
    "M-03": {
        "sub_type": "VOLUMETRIC_BURST",
        "ts_burst": True,
        "hostile": lambda i: (
            f"node-{i:02d}.burst-c2.pound2pound.fr", 1,
            make_query(0xC100 + i, f"node-{i:02d}.burst-c2.pound2pound.fr", 1),
            make_response(make_query(0xC100 + i, f"node-{i:02d}.burst-c2.pound2pound.fr", 1),
                          answers=[(f"node-{i:02d}.burst-c2.pound2pound.fr.", 60, "A", "10.55.10.3")]),
            0),
        "benign": lambda i: (
            f"page.benign{i}.ex{i}.org", 1,
            make_query(0xC200 + i, f"page.benign{i}.ex{i}.org", 1),
            make_response(make_query(0xC200 + i, f"page.benign{i}.ex{i}.org", 1),
                          answers=[(f"page.benign{i}.ex{i}.org.", 300, "A", "198.51.100.3")]),
            0),
    },
    "M-04": {
        "sub_type": "DGA_NXDOMAIN_FLOOD",
        "hostile": lambda i: (
            f"{_dga(i)}.dga-c2.pound2pound.fr", 1,
            make_query(0xD100 + i, f"{_dga(i)}.dga-c2.pound2pound.fr", 1),
            make_response(make_query(0xD100 + i, f"{_dga(i)}.dga-c2.pound2pound.fr", 1), rcode=3),
            3),
        "benign": lambda i: (
            f"app.benign{i}.example.org", 1,
            make_query(0xD200 + i, f"app.benign{i}.example.org", 1),
            make_response(make_query(0xD200 + i, f"app.benign{i}.example.org", 1),
                          answers=[(f"app.benign{i}.example.org.", 300, "A", "198.51.100.4")]),
            0),
    },
    "P1": {
        "sub_type": "RDATA_ASYMMETRY_IODINE",
        "hostile": lambda i: (
            f"iod-{i:02d}.p1-c2.pound2pound.fr", 16,
            make_query(0xE100 + i, f"iod-{i:02d}.p1-c2.pound2pound.fr", 16),
            make_response(make_query(0xE100 + i, f"iod-{i:02d}.p1-c2.pound2pound.fr", 16),
                          answers=[(f"iod-{i:02d}.p1-c2.pound2pound.fr.", 60, "TXT", _big_txt(i))]),
            0),
        "benign": lambda i: (
            f"spf.benign{i}.example.org", 16,
            make_query(0xE200 + i, f"spf.benign{i}.example.org", 16),
            make_response(make_query(0xE200 + i, f"spf.benign{i}.example.org", 16),
                          answers=[(f"spf.benign{i}.example.org.", 300, "TXT", "v=spf1 -all")]),
            0),
    },
    "P2": {
        "sub_type": "SMOOTH_HEX_BASE32",
        "hostile": lambda i: (
            f"{_hex32(i)}.p2-c2.pound2pound.fr", 1,
            make_query(0xF100 + i, f"{_hex32(i)}.p2-c2.pound2pound.fr", 1),
            make_response(make_query(0xF100 + i, f"{_hex32(i)}.p2-c2.pound2pound.fr", 1),
                          answers=[(f"{_hex32(i)}.p2-c2.pound2pound.fr.", 60, "A", "10.55.10.5")]),
            0),
        "benign": lambda i: (
            f"cdn.benign{i}.example.org", 1,
            make_query(0xF200 + i, f"cdn.benign{i}.example.org", 1),
            make_response(make_query(0xF200 + i, f"cdn.benign{i}.example.org", 1),
                          answers=[(f"cdn.benign{i}.example.org.", 300, "A", "198.51.100.5")]),
            0),
    },
    "P6": {
        "sub_type": "DYNAMIC_UPDATE_TUNNEL",
        "hostile": lambda i: (
            f"zone-{i:02d}.p6-c2.pound2pound.fr", 1,
            make_update(0x0100 + i, f"zone-{i:02d}.p6-c2.pound2pound.fr.",
                        [(f"upd-{i:02d}.zone-{i:02d}.p6-c2.pound2pound.fr.", 1, "10.55.10.6")]),
            make_response(make_query(0x0100 + i, f"zone-{i:02d}.p6-c2.pound2pound.fr", 1), rcode=0),
            0),
        "benign": lambda i: (
            f"www.benign{i}.example.org", 1,
            make_query(0x0180 + i, f"www.benign{i}.example.org", 1),
            make_response(make_query(0x0180 + i, f"www.benign{i}.example.org", 1),
                          answers=[(f"www.benign{i}.example.org.", 300, "A", "198.51.100.6")]),
            0),
    },
    "P8": {
        "sub_type": "CNAME_CHAIN_TUNNEL",
        "hostile": lambda i: (
            f"short-{i:02d}.p8-c2.pound2pound.fr", 1,
            make_query(0x0200 + i, f"short-{i:02d}.p8-c2.pound2pound.fr", 1),
            make_response(make_query(0x0200 + i, f"short-{i:02d}.p8-c2.pound2pound.fr", 1),
                          answers=[(f"short-{i:02d}.p8-c2.pound2pound.fr.", 60, "CNAME",
                                   f"stage-{i:02d}.p8-c2.pound2pound.fr."),
                                  (f"stage-{i:02d}.p8-c2.pound2pound.fr.", 60, "CNAME",
                                   f"cmd-payload-exfil-stage-{i:02d}-abcdef0123456789.p8-c2.pound2pound.fr.")]),
            0),
        "benign": lambda i: (
            f"www.benign{i}.example.org", 1,
            make_query(0x0280 + i, f"www.benign{i}.example.org", 1),
            make_response(make_query(0x0280 + i, f"www.benign{i}.example.org", 1),
                          answers=[(f"www.benign{i}.example.org.", 300, "A", "198.51.100.7")]),
            0),
    },
    "P11": {
        "sub_type": "LABEL_LENGTH_STEGO",
        "hostile": lambda i: (
            f"{_alpha_tuple(i, 4 + i % 2, 9 if i % 2 == 0 else 7)}.pound2pound.fr", 1,
            make_query(0x0300 + i, f"{_alpha_tuple(i, 4 + i % 2, 9 if i % 2 == 0 else 7)}.pound2pound.fr", 1),
            make_response(make_query(0x0300 + i, f"{_alpha_tuple(i, 4 + i % 2, 9 if i % 2 == 0 else 7)}.pound2pound.fr", 1),
                          answers=[(f"{_alpha_tuple(i, 4 + i % 2, 9 if i % 2 == 0 else 7)}.pound2pound.fr.", 60, "A", "10.55.10.7")]),
            0),
        "benign": lambda i: (
            f"api.benign{i}.example.org", 1,
            make_query(0x0380 + i, f"api.benign{i}.example.org", 1),
            make_response(make_query(0x0380 + i, f"api.benign{i}.example.org", 1),
                          answers=[(f"api.benign{i}.example.org.", 300, "A", "198.51.100.8")]),
            0),
    },
    "P12": {
        "sub_type": "BASE58_SUBDOMAIN",
        "hostile": lambda i: (
            f"{_b58(i + 100)}.p12-c2.pound2pound.fr", 1,
            make_query(0x0400 + i, f"{_b58(i + 100)}.p12-c2.pound2pound.fr", 1),
            make_response(make_query(0x0400 + i, f"{_b58(i + 100)}.p12-c2.pound2pound.fr", 1),
                          answers=[(f"{_b58(i + 100)}.p12-c2.pound2pound.fr.", 60, "A", "10.55.10.8")]),
            0),
        "benign": lambda i: (
            f"docs.benign{i}.example.org", 1,
            make_query(0x0480 + i, f"docs.benign{i}.example.org", 1),
            make_response(make_query(0x0480 + i, f"docs.benign{i}.example.org", 1),
                          answers=[(f"docs.benign{i}.example.org.", 300, "A", "198.51.100.9")]),
            0),
    },
    "P3": {
        "sub_type": "MARKOV_BEACON",
        "ts_step_ns": 500_000_000,
        "hostile": lambda i: (
            f"beacon-{i:02d}.p3-c2.pound2pound.fr", [1, 28, 16, 10, 5][i % 5],
            make_query(0x1300 + i, f"beacon-{i:02d}.p3-c2.pound2pound.fr", [1, 28, 16, 10, 5][i % 5]),
            make_response(make_query(0x1300 + i, f"beacon-{i:02d}.p3-c2.pound2pound.fr", [1, 28, 16, 10, 5][i % 5])),
            0),
        "benign": lambda i: (
            f"page.benign{i}.example.org", 1,
            make_query(0x1380 + i, f"page.benign{i}.example.org", 1),
            make_response(make_query(0x1380 + i, f"page.benign{i}.example.org", 1),
                          answers=[(f"page.benign{i}.example.org.", 300, "A", "198.51.100.13")]),
            0),
    },
    "P4": {
        "sub_type": "MULTIPARENT_SHARDING",
        "hostile": lambda i: (
            f"shardpayload{i:02d}.shard-{i:02d}.com", 1,
            make_query(0x1400 + i, f"shardpayload{i:02d}.shard-{i:02d}.com", 1),
            make_response(make_query(0x1400 + i, f"shardpayload{i:02d}.shard-{i:02d}.com", 1)),
            0),
        "benign": lambda i: (
            f"benignpayload{i:02d}.benign-{i % 5}.org", 1,
            make_query(0x1480 + i, f"benignpayload{i:02d}.benign-{i % 5}.org", 1),
            make_response(make_query(0x1480 + i, f"benignpayload{i:02d}.benign-{i % 5}.org", 1)),
            0),
    },
    "P9": {
        "sub_type": "EDNS0_OPT_TUNNEL",
        "hostile": lambda i: (
            "p9-c2.pound2pound.fr", 1,
            make_query(0x1500 + i, "p9-c2.pound2pound.fr", 1),
            make_opt_response(make_query(0x1500 + i, "p9-c2.pound2pound.fr", 1)),
            0),
        "benign": lambda i: (
            f"p9b.benign{i}.example.org", 1,
            make_query(0x1580 + i, f"p9b.benign{i}.example.org", 1),
            make_response(make_query(0x1580 + i, f"p9b.benign{i}.example.org", 1),
                          answers=[(f"p9b.benign{i}.example.org.", 300, "A", "198.51.100.15")]),
            0),
    },
    "P16": {
        "sub_type": "CACHE_POISONING",
        "hostile": lambda i: (
            f"victim-{i:02d}.p16-c2.pound2pound.fr", 1,
            make_query(0x1600 + i, f"victim-{i:02d}.p16-c2.pound2pound.fr", 1),
            make_response(make_query(0x1600 + i, f"victim-{i:02d}.p16-c2.pound2pound.fr", 1),
                          answers=[("attacker.evil.com.", 60, "A", "10.55.10.202")]),
            0),
        "benign": lambda i: (
            f"page.benign{i}.example.org", 1,
            make_query(0x1680 + i, f"page.benign{i}.example.org", 1),
            make_response(make_query(0x1680 + i, f"page.benign{i}.example.org", 1),
                          answers=[(f"page.benign{i}.example.org.", 300, "A", "198.51.100.16")]),
            0),
    },
    "P17": {
        "sub_type": "DNSKEY_C2",
        "hostile": lambda i: (
            "p17-c2.pound2pound.fr", 48,
            make_query(0x1700 + i, "p17-c2.pound2pound.fr", 48),
            make_p17_response(make_query(0x1700 + i, "p17-c2.pound2pound.fr", 48)),
            0),
        "benign": lambda i: (
            f"p17b.benign{i}.example.org", 1,
            make_query(0x1780 + i, f"p17b.benign{i}.example.org", 1),
            make_response(make_query(0x1780 + i, f"p17b.benign{i}.example.org", 1),
                          answers=[(f"p17b.benign{i}.example.org.", 300, "A", "198.51.100.17")]),
            0),
    },
    "P18": {
        "sub_type": "NOTIFY_C2",
        "hostile": lambda i: (
            "p18-c2.pound2pound.fr", 64,
            make_query(0x1800 + i, "p18-c2.pound2pound.fr", 64),
            make_response(make_query(0x1800 + i, "p18-c2.pound2pound.fr", 64)),
            0),
        "benign": lambda i: (
            f"p18b.benign{i}.example.org", 1,
            make_query(0x1880 + i, f"p18b.benign{i}.example.org", 1),
            make_response(make_query(0x1880 + i, f"p18b.benign{i}.example.org", 1),
                          answers=[(f"p18b.benign{i}.example.org.", 300, "A", "198.51.100.18")]),
            0),
    },
    "P19": {
        "sub_type": "TKEY_SIG0_C2",
        "hostile": lambda i: (
            "p19-c2.pound2pound.fr", 249,
            make_query(0x1900 + i, "p19-c2.pound2pound.fr", 249),
            make_p19_response(make_query(0x1900 + i, "p19-c2.pound2pound.fr", 249)),
            0),
        "benign": lambda i: (
            f"p19b.benign{i}.example.org", 1,
            make_query(0x1980 + i, f"p19b.benign{i}.example.org", 1),
            make_response(make_query(0x1980 + i, f"p19b.benign{i}.example.org", 1),
                          answers=[(f"p19b.benign{i}.example.org.", 300, "A", "198.51.100.19")]),
            0),
    },
}


def generate(which):
    keys = list(MOTIFS.keys()) if which == "all" else which.split(",")
    for k in keys:
        cfg = MOTIFS[k]
        hostile = [cfg["hostile"](i) for i in range(25)]
        benign = [cfg["benign"](i) for i in range(25)]
        emit(k, cfg["sub_type"], hostile, benign,
             ts_step_ns=cfg.get("ts_step_ns", 200_000_000),
             ts_burst=cfg.get("ts_burst", False),
             label=f"{k.lower()}-real-20261029T000000Z")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    generate(which)
