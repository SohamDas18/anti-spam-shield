import re
from urllib.parse import urlparse

# Suspicious keywords commonly seen in phishing and scam URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'verification', 'account', 'secure', 'security',
    'update', 'password', 'confirm', 'confirmation', 'payment', 'banking',
    'bank', 'signin', 'auth', 'claim', 'bonus', 'prize', 'lottery',
    'free', 'wallet', 'refund', 'authenticate', 'billing', 'invoice'
]

# Suspicious file extensions pointing to executable or malicious downloads
DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.dll', '.zip', '.iso'
]

# High-reputation legitimate domains widely shared in normal communication
REPUTABLE_DOMAINS = [
    'youtube.com', 'youtu.be', 'google.com', 'docs.google.com', 'drive.google.com',
    'github.com', 'wikipedia.org', 'linkedin.com', 'instagram.com', 'spotify.com',
    'twitter.com', 'x.com', 'medium.com', 'stackoverflow.com', 'zoom.us', 'meet.google.com',
    'microsoft.com', 'apple.com', 'amazon.in', 'amazon.com', 'flipkart.com'
]

# Regex pattern to match URLs
URL_PATTERN = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+)',
    re.IGNORECASE
)

# Regex to check if host is an IP address
IPV4_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$')

def extract_urls(text):
    """Finds all URLs within the given text."""
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    # Clean trailing punctuation from URLs
    cleaned = []
    for u in matches:
        u = u.rstrip('.,);:!?\'"')
        if u not in cleaned:
            cleaned.append(u)
    return cleaned

def analyze_url(url):
    """
    Extracts structural and lexical risk features from a URL.
    Returns: dictionary of features and risk flags.
    """
    # Normalize URL if missing scheme
    parsed_url = url
    if not url.startswith(('http://', 'https://')):
        parsed_url = 'http://' + url

    parsed = urlparse(parsed_url)
    hostname = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    # Feature 1: Length
    url_length = len(url)
    is_long_url = url_length > 75

    # Feature 2: Number of dots
    dot_count = hostname.count('.')
    subdomain_count = max(0, dot_count - 1)
    has_multiple_subdomains = subdomain_count >= 3

    # Feature 3: Special characters
    special_chars = sum(full_url.count(c) for c in ['@', '?', '=', '&', '%', '-', '_'])
    has_at_symbol = '@' in full_url

    # Feature 4: IP Address instead of domain
    has_ip = bool(IPV4_PATTERN.match(hostname))

    # Feature 5: HTTPS usage
    is_https = url.lower().startswith('https://')

    # Feature 6: Suspicious keywords
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    has_suspicious_keywords = len(matched_keywords) > 0

    # Feature 7: Dangerous extensions
    has_dangerous_ext = any(path.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    matched_extension = next((ext for ext in DANGEROUS_EXTENSIONS if path.endswith(ext)), None)

    # Feature 8: Redirect indicators (e.g. // in path or multiple http)
    has_redirect_indicators = full_url.count('http') > 1 or '//' in parsed.path

    score = 0.10
    reasons = []

    # Check Reputable Domain
    is_reputable = any(hostname.endswith(d) or hostname == d for d in REPUTABLE_DOMAINS)
    if is_reputable and not has_dangerous_ext:
        score = 0.02
        reasons.append(f"Verified reputable web platform / mainstream service ({hostname})")
    else:
        if has_ip:
            score += 0.35
            reasons.append("URL uses a raw IP address instead of a registered domain name")

        if has_dangerous_ext:
            score += 0.40
            reasons.append(f"URL directly links to an executable/dangerous file ({matched_extension})")

        if has_suspicious_keywords:
            score += min(0.30, len(matched_keywords) * 0.12)
            reasons.append(f"Contains security-sensitive terms: {', '.join(matched_keywords[:3])}")

        if has_at_symbol:
            score += 0.25
            reasons.append("Contains '@' symbol used to obscure true destination hostname")

        if has_multiple_subdomains:
            score += 0.20
            reasons.append(f"Excessive subdomain nesting ({subdomain_count} subdomains)")

        if is_long_url:
            score += 0.15
            reasons.append(f"Abnormally long URL length ({url_length} characters)")

        if not is_https:
            score += 0.10
            reasons.append("Insecure HTTP protocol without TLS encryption")

        if has_redirect_indicators:
            score += 0.20
            reasons.append("Contains secondary redirect / destination camouflage indicators")

    url_risk_prob = min(0.99, max(0.01, score))

    return {
        'url': url,
        'url_length': url_length,
        'hostname': hostname,
        'dot_count': dot_count,
        'subdomain_count': subdomain_count,
        'special_char_count': special_chars,
        'has_ip': has_ip,
        'is_https': is_https,
        'matched_keywords': matched_keywords,
        'has_dangerous_ext': has_dangerous_ext,
        'matched_extension': matched_extension,
        'url_risk_prob': round(url_risk_prob, 4),
        'reasons': reasons
    }

if __name__ == '__main__':
    test_urls = [
        "https://google.com/search",
        "http://192.168.1.100/login",
        "https://account-verify-portal.bank.secure.com/login.php",
        "https://example.com/invoice.exe"
    ]
    for u in test_urls:
        print(u, "->", analyze_url(u))
