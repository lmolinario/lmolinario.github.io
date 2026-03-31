import re


DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    return domain


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.fullmatch(domain))