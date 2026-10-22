"""CISA Known Exploited Vulnerabilities catalog."""

from . import net

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cache = {}


def catalog():
    """{CVE id: {"date_added", "due_date", "ransomware"}}"""
    if "kev" not in _cache:
        data = net.get_json(URL, source="CISA KEV")
        out = {}
        for v in data.get("vulnerabilities") or []:
            out[v["cveID"]] = {
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
            }
        _cache["kev"] = out
    return _cache["kev"]


def lookup(ids):
    """KEV record for the first of `ids` that is listed, else None."""
    cat = catalog()
    for i in sorted(ids):
        if i in cat:
            rec = dict(cat[i])
            rec["cve"] = i
            return rec
    return None
