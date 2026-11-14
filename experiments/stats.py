"""Summary statistics used for every reported number."""
import math


def quantile(values, q):
    """Nearest-rank quantile on the sorted sample, index (n-1)q rounded half up
    (the rule of the Rust benchmarks); used for the quartiles."""
    v = sorted(values)
    return v[int((len(v) - 1) * q + 0.5)]


def median(values):
    """Conventional median: the middle value, or the mean of the two middle values."""
    v = sorted(values)
    m = len(v) // 2
    return v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2


def summarize(values):
    """Return n, mean, sample standard deviation, median, p25 and p75 of a list of numbers."""
    n = len(values)
    if n == 0:
        return {"n": 0}
    mean = sum(values) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1)) if n > 1 else 0.0
    return {
        "n": n,
        "mean": round(mean, 4),
        "std": round(std, 4),
        "median": round(median(values), 4),
        "p25": round(quantile(values, 0.25), 4),
        "p75": round(quantile(values, 0.75), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }
