"""Table 7: lower bound 8l/R on transmission time. Pure arithmetic, device independent."""


def lower_bounds(payload_bytes, rates_bps):
    """Seconds needed to send payload_bytes at each throughput (bits per second)."""
    return {str(g): round(8 * payload_bytes / g, 4) for g in rates_bps}


def table(payloads, rates_bps):
    """payloads: {label: bytes}. Returns {label: {"bytes": L, "seconds": {rate: t}}}."""
    return {k: {"bytes": v, "seconds": lower_bounds(v, rates_bps)} for k, v in payloads.items()}
