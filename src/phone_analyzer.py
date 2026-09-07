import re

# Comprehensive regex patterns for phone numbers and SMS sender shortcodes
PHONE_REGEX = re.compile(
    r'(?:'
    # International with + (e.g. +91 98765 43210, +1 (555) 349-2011, +234 803 123 4567)
    r'(?:\+|00)\d{1,3}[-.\s]?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{3,5}'
    r'|'
    # Toll-free / Emergency numbers (1800-XXX-XXXX, 1860-XXX-XXXX)
    r'(?:1800|1860)[-.\s]?\d{3}[-.\s]?\d{4}'
    r'|'
    # Standard 10-digit mobile numbers (Indian 6-9 prefix or standard format)
    r'(?<!\d)(?:(?:\+91|91|0)?[6-9]\d{9})(?!\d)'
    r')',
    re.IGNORECASE
)

# WhatsApp link pattern (wa.me/XXXXXXXXXX)
WHATSAPP_LINK_REGEX = re.compile(r'(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send\?phone=)(\d+)', re.IGNORECASE)

# TRAI-registered standard Indian transactional SMS sender ID (e.g. VK-HDFCBK, AD-SBIPAY, BZ-ICICIB)
OFFICIAL_SMS_SHORTCODE_REGEX = re.compile(r'^[A-Z]{2}-[A-Z0-9]{5,6}$', re.IGNORECASE)

COUNTRY_CODES = {
    '91': {'country': 'India', 'risk': 'NORMAL'},
    '1': {'country': 'United States / Canada', 'risk': 'NORMAL'},
    '44': {'country': 'United Kingdom', 'risk': 'NORMAL'},
    '234': {'country': 'Nigeria', 'risk': 'HIGH'},
    '92': {'country': 'Pakistan', 'risk': 'HIGH'},
    '7': {'country': 'Russia / Kazakhstan', 'risk': 'MEDIUM'},
    '86': {'country': 'China', 'risk': 'MEDIUM'},
    '62': {'country': 'Indonesia', 'risk': 'MEDIUM'},
    '880': {'country': 'Bangladesh', 'risk': 'NORMAL'},
    '254': {'country': 'Kenya', 'risk': 'MEDIUM'},
    '63': {'country': 'Philippines', 'risk': 'MEDIUM'}
}

# Explicit vishing / fraudulent callback lures
VISHING_SCAM_KEYWORDS = [
    'helpline', 'customer care', 'support team', 'executive', 'officer',
    'manager', 'electricity officer', 'loan officer', 'call executive',
    'tollfree', 'toll-free', 'dial now to unblock', 'call immediately to avoid',
    'call our officer', 'contact manager', 'contact customer care'
]

def extract_phone_numbers(text):
    """Finds all phone numbers and WhatsApp links inside text."""
    if not text:
        return []
    
    extracted = []
    
    # 1. Regex phone matches
    for match in PHONE_REGEX.findall(text):
        num_clean = match.strip().rstrip('.,);:!?')
        # Discard trivial short numbers or dates (like 2026)
        digits_only = re.sub(r'\D', '', num_clean)
        if len(digits_only) >= 7 and num_clean not in extracted:
            extracted.append(num_clean)

    # 2. WhatsApp links
    for wa_match in WHATSAPP_LINK_REGEX.findall(text):
        if wa_match not in extracted:
            extracted.append(f"+{wa_match} (WhatsApp)")

    return extracted

def is_phone_number_sender(sender):
    """Detects if sender is a phone number or SMS sender ID instead of an email."""
    if not sender or '@' in sender:
        return False
    # Check if contains digits or is a TRAI shortcode
    digits = re.sub(r'\D', '', sender)
    return len(digits) >= 6 or OFFICIAL_SMS_SHORTCODE_REGEX.match(sender.strip()) is not None

def analyze_phone_sender(sender, text_content=""):
    """
    Evaluates whether the sender of an SMS message is legitimate or spoofed.
    Rule: Banks/Government never send official warnings from personal 10-digit phone numbers!
    """
    clean_sender = sender.strip() if sender else ""
    digits = re.sub(r'\D', '', clean_sender)
    text_lower = text_content.lower()

    is_bank_or_gov_claim = any(kw in text_lower for kw in [
        'bank', 'sbi', 'hdfc', 'icici', 'axis', 'yono', 'kyc', 'pan',
        'electricity', 'power cut', 'bill', 'income tax', 'refund', 'trai'
    ])

    reasons = []
    sender_risk = "LOW"
    score = 0.10

    # Normalize domestic phone length (strip 91 or leading 0)
    if len(digits) == 12 and digits.startswith('91'):
        core_digits = digits[2:]
    elif len(digits) == 11 and digits.startswith('0'):
        core_digits = digits[1:]
    else:
        core_digits = digits

    # If message claims to be a bank/gov/utility agency but sender is a personal mobile number
    if is_bank_or_gov_claim and len(core_digits) == 10:
        sender_risk = "CRITICAL"
        score = 0.90
        reasons.append("Impersonation Alert: Financial or Utility alert sent from a personal 10-digit mobile number instead of an official registered SMS header.")

    elif clean_sender.startswith(('+234', '+92', '+62')) and is_bank_or_gov_claim:
        sender_risk = "CRITICAL"
        score = 0.95
        reasons.append("High-Risk Foreign Origin: Domestic banking/tax claims originating from an overseas mobile carrier.")

    elif OFFICIAL_SMS_SHORTCODE_REGEX.match(clean_sender):
        sender_risk = "LOW"
        score = 0.05
        reasons.append(f"Official format: Verified institutional SMS sender header ({clean_sender}).")

    return {
        'sender': clean_sender,
        'is_phone_sender': True,
        'sender_risk': sender_risk,
        'score': score,
        'reasons': reasons
    }

def analyze_embedded_phone(number, text_context=""):
    """
    Extracts country, type, and callback deception vectors for a phone number embedded in a message.
    """
    digits = re.sub(r'\D', '', number)
    text_lower = text_context.lower()

    country = "Unknown / International"
    origin_risk = "NORMAL"

    # Identify Country Code
    for code, info in sorted(COUNTRY_CODES.items(), key=lambda x: len(x[0]), reverse=True):
        if digits.startswith(code):
            country = info['country']
            origin_risk = info['risk']
            break

    # If 10 digits starting with 6-9 without +, assume domestic India
    if len(digits) == 10 and digits[0] in '6789':
        country = "India (Mobile)"

    # Identify Number Type
    is_toll_free = bool(re.match(r'^(?:1800|1860|800|888)', digits))
    number_type = "Toll-Free Helpline" if is_toll_free else ("WhatsApp Contact" if "whatsapp" in number.lower() else "Standard Mobile")

    # Check Callback Lure / Vishing Trap (Only true if paired with institutional or threat context)
    has_scam_threat = any(w in text_lower for w in ['power', 'electricity', 'kyc', 'pan', 'blocked', 'lottery', 'kbc', 'fine', 'penalty', 'disconnect', 'suspended', 'deactivated'])
    has_callback_lure = any(kw in text_lower for kw in VISHING_SCAM_KEYWORDS) or (has_scam_threat and any(c in text_lower for c in ['call', 'dial', 'contact']))
    
    score = 0.05
    flags = []

    if origin_risk == 'HIGH':
        score += 0.50
        flags.append(f"Originates from high-risk jurisdiction for telecommunication scams ({country})")

    if has_callback_lure:
        score += 0.55
        flags.append("Callback Trap: Message prompts user to call this number to resolve urgent institutional issues or claim prizes")

    if ("whatsapp" in number.lower() or "wa.me" in text_lower) and any(kw in text_lower for kw in ['earn', 'job', 'part-time', 'daily', 'invest', 'crypto', 'bonus', 'salary']):
        score += 0.45
        flags.append("WhatsApp Scam Redirection: Scammer attempts to move communication off-platform for task/investment scam")

    if is_toll_free and any(kw in text_lower for kw in ['winner', 'lottery', 'prize', 'reward']):
        score += 0.45
        flags.append("Fake Helpline: Unregistered toll-free number used as prize collection lure")

    phone_risk_prob = min(0.99, max(0.02, score))

    risk_level = "LOW"
    if phone_risk_prob >= 0.50:
        risk_level = "HIGH"
    elif phone_risk_prob >= 0.25:
        risk_level = "MEDIUM"

    return {
        'phone_number': number,
        'digits': digits,
        'country': country,
        'number_type': number_type,
        'has_callback_lure': has_callback_lure,
        'risk_probability': round(phone_risk_prob * 100, 1),
        'risk_level': risk_level,
        'flags': flags
    }

if __name__ == '__main__':
    msg = "Dear user, electricity bill pending. Power disconnects tonight. Call officer at +91 98765 43210 or WhatsApp +1 (555) 349-2011"
    nums = extract_phone_numbers(msg)
    print("Found numbers:", nums)
    for n in nums:
        print(analyze_embedded_phone(n, msg))
