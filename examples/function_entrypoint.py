class Tainted:
    """Marker annotation: parameters typed with this are attacker-controlled
    entry points (e.g. an HTTP handler argument), even with no explicit
    input()/request.get() call visible in this function."""
    pass


def run_report(report_name: Tainted):
    # VULNERABLE: attacker-controlled parameter flows straight into eval().
    result = eval(report_name)
    return result


def safe_lookup(key: Tainted):
    allowed = {"a": 1, "b": 2}
    # This never reaches a sink at all -- dict lookup isn't in our sink list,
    # so nothing is flagged here (demonstrates the tool only reports real
    # sink reachability, not "tainted data touched anywhere").
    return allowed.get(key)
