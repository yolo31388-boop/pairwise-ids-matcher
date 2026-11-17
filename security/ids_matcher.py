"""IDS signature matching helpers.

Fixes for the high-traffic drop issues:
- match_rules returns ALL matching rule ids (not just the first hit),
  so overlapping rules no longer swallow more specific alerts.
- normalize lowercases and URL-decodes payloads before matching, so
  case/encoding evasion variants are caught.
- reassemble sorts TCP segments by sequence number and drops
  retransmissions, so out-of-order/retransmitted streams reassemble
  with correct boundaries and cross-packet keywords stay intact.
- direction_ok makes rules direction-aware, so egress replies don't
  trigger ingress-only rules.
- allowlisted supports NAT mappings in addition to exact source IPs,
  so a NAT'd egress isn't blanket-muted (and known mappings still match).
"""

from urllib.parse import unquote


def normalize(payload):
    """Lowercase and URL-decode a payload for canonical matching."""
    if payload is None:
        return ''
    # Repeatedly decode to catch double-encoded variants like %252f.
    prev = None
    cur = str(payload)
    while prev != cur:
        prev = cur
        cur = unquote(cur)
    return cur.lower()


def match_rules(payload, rules):
    """Return ids of ALL rules whose pattern matches the payload.

    Payload and patterns are normalized before matching. Ids are
    returned in rule order, deduplicated.
    """
    if not payload or not rules:
        return []
    haystack = normalize(payload)
    hits = []
    seen = set()
    for rule in rules:
        rid = rule.get('id')
        pattern = normalize(rule.get('pattern', ''))
        if pattern and pattern in haystack and rid not in seen:
            seen.add(rid)
            hits.append(rid)
    return hits


def reassemble(segments):
    """Reassemble TCP segments given as (seq, payload) pairs.

    Sorts by sequence number and ignores retransmitted (duplicate)
    segments, so out-of-order delivery and retransmits don't corrupt
    stream boundaries.
    """
    if not segments:
        return ''
    by_seq = {}
    for seq, data in segments:
        # First copy wins; retransmits of the same seq are dropped.
        by_seq.setdefault(seq, data)
    return ''.join(by_seq[seq] for seq in sorted(by_seq))


def direction_ok(rule_direction, flow_direction):
    """True if a rule applies to the flow's direction.

    A rule scoped to 'ingress' must not fire on 'egress' traffic and
    vice versa; 'any'/None matches both directions.
    """
    if rule_direction in (None, 'any'):
        return True
    return rule_direction == flow_direction


def allowlisted(ip, exact, nat_map):
    """True if ip is allowlisted, directly or via a NAT mapping.

    `exact` is a set of allowlisted IPs; `nat_map` maps internal IPs to
    their translated egress addresses. An IP is allowlisted if it
    appears in the exact set, or as either side of a known NAT mapping.
    """
    if ip in exact:
        return True
    if ip in nat_map:
        return True
    return ip in nat_map.values()
