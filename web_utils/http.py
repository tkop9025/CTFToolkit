from requests import Session
import os

# Core


def init_session(proxies=False, verify_ssl=False, timeout=5):
    s = Session()
    s.verify = verify_ssl

    if proxies:
        proxy_dict = {}
        http_url = os.getenv("HTTP_PROXY")
        https_url = os.getenv("HTTPS_PROXY")
        socks_url = os.getenv("SOCKS5_PROXY")

        if http_url:
            proxy_dict["http"] = http_url
        if https_url:
            proxy_dict["https"] = https_url
        if socks_url:
            proxy_dict["socks5"] = socks_url

        try:
            s.proxies.update(proxy_dict)
        except Exception as e:
            raise RuntimeError(f"Proxy Error: {e}")

    return s


def log(req, resp):
    print(f"Request: {req} \n")
    print(f"Response: {resp} \n")


def get(s: Session, url: str, *, params=None, timeout=5):
    return s.get(url, params=params or {}, timeout=timeout)


def post(s: Session, url: str, *, params=None, timeout=5):
    return s.post(url, params=params or {}, timeout=timeout)


# Helpers


def add_header(s: Session, key, val):
    s.headers[key] = val


def get_headers(s: Session):
    return s.headers


def add_cookie(s: Session, key, val):
    s.cookies[key] = val


def get_cookies(s: Session):
    return s.cookies
