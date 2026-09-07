import os
import sys
import re
import joblib

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.preprocessing import clean_text
from src.url_analyzer import extract_urls, analyze_url
from src.phone_analyzer import (
    extract_phone_numbers,
    analyze_embedded_phone,
    is_phone_number_sender,
    analyze_phone_sender
)
from src.risk_analyzer import calculate_risk
from db import db, normalize_identifier

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model')

# LRU Cache for translation of native language messages
_TRANSLATION_CACHE = {}

def translate_native_message(text):
    """
    Translates non-English native language text (Hindi, Bengali, Marathi, Tamil, Telugu, etc.)
    into English so that the English-trained ML model and threat heuristic rules
    can evaluate the semantic context accurately. Returns translated text.
    """
    if not text or not isinstance(text, str):
        return text or ""
    # Check if text contains non-ASCII characters (native scripts: Devanagari, Bengali, Tamil, etc.)
    has_non_ascii = any(ord(c) > 127 for c in text)
    if not has_non_ascii:
        return text
    
    snippet = text.strip()[:1200]
    if snippet in _TRANSLATION_CACHE:
        return _TRANSLATION_CACHE[snippet]
    
    try:
        from deep_translator import GoogleTranslator
        translated = GoogleTranslator(source='auto', target='en').translate(snippet)
        res = translated if translated else text
        if len(_TRANSLATION_CACHE) > 500:
            _TRANSLATION_CACHE.clear()
        _TRANSLATION_CACHE[snippet] = res
        return res
    except Exception:
        return text

# Personal / Conversational cues (friends, family, colleagues across all native languages)
CONVERSATIONAL_MARKERS = [
    # English
    'hey', 'hi', 'hello', 'bro', 'bhai', 'bhaiya', 'dude', 'yaar', 'man', 'buddy',
    'dear friend', 'catch up', 'lunch', 'dinner', 'reach home', 'reached', 'call me', 'reach out',
    'are you free', 'let me know', 'thanks a lot', 'talk later', 'see you',
    'haha', 'lol', 'assignment', 'notes', 'meeting',
    'gpay', 'phonepe', 'paytm', 'upi', 'movie', 'ticket', 'metro', 'station', 'traffic',
    'homework', 'class', 'college', 'exam', 'birthday', 'congrats', 'congratulations',
    'lost my phone', 'new number', 'temporary number', 'save it', 'save my number',
    'pick up', 'give me a ring', 'sorry for late', 'how are you', 'whats up', "what's up",
    
    # Bengali Script (বাংলা হরফ) & Banglish
    'ভাই', 'দাদা', 'দিদি', 'মা', 'বাবা', 'বন্ধু', 'কেমন আছিস', 'কেমন আছেন', 'ফোন কর', 'ফোন করো',
    'কল কর', 'টাকা পাঠা', 'পৌঁছে গেছি', 'পৌঁছে গেছিস', 'শুভ জন্মদিন', 'দেখা করবি', 'দেখা করব', 'ফ্রি আছিস', 'কী খবর',
    'kemon achis', 'kemon acho', 'ki khobor', 'kalke', 'ashbi', 'taka patha', 'call kor',
    'call koris', 'dekha korbo', 'pouche gechi', 'shubho jonmodin',

    # Hindi Script (हिन्दी देवनागरी) & Hinglish
    'भाई', 'दोस्त', 'माँ', 'पापा', 'कैसा है', 'कैसी है', 'क्या हाल है', 'फोन कर', 'कॉल कर',
    'पैसे भेज', 'पहुंच गया', 'पहुंच गए', 'मिलते हैं', 'जन्मदिन मुबारक', 'फ्री है', 'बात कर', 'कहाँ है',
    'kaisa hai', 'kaisi hai', 'kya hal hai', 'kahan hai', 'ghar pahunch gaya', 'call kar',
    'phone kar', 'milte hai', 'paise bhej de', 'free hoke call', 'kya kar raha hai', 'shukriya',

    # Marathi (मराठी)
    'भावा', 'कसा आहेस', 'कशी आहेस', 'काय चाललंय', 'फोन कर', 'घरी पोहोचलो', 'भेटूया', 'पैसे पाठव',
    'bhawa', 'kasa ahes', 'ghari pohochlo', 'call kar',

    # Tamil (தமிழ்) & Tanglish
    'மச்சான்', 'நண்பா', 'எப்படி இருக்கீங்க', 'எப்படி இருக்க', 'போன் பண்ணு', 'வீட்டுக்கு வந்துட்டேன்', 'ஃப்ரீ',
    'machan', 'machi', 'nanba', 'eppadi irukka', 'call pannu', 'veetuku vanthuten',

    # Telugu (తెలుగు) & Tenglish
    'బావున్నారా', 'ఎలా ఉన్నావు', 'ఫోన్ చేయి', 'ఇంటికి వచ్చాను', 'కలుద్దాం', 'స్నేహితుడా',
    'macha', 'bava', 'ela unnav', 'call cheyi', 'intiki vachava',

    # Gujarati (ગુજરાતી)
    'કેમ છો', 'ભાઈ', 'ફોન કરજે', 'ઘરે પહોંચી ગયો', 'મળીએ', 'મિત્ર', 'kem cho', 'phone karje',

    # Punjabi (ਪੰਜਾਬੀ)
    'ਕਿਵੇਂ ਹੋ', 'ਵੀਰੇ', 'ਭਰਾ', 'ਫੋਨ ਕਰੀਂ', 'ਘਰ ਪਹੁੰਚ ਗਿਆ', 'ਮਿਲਦੇ ਹਾਂ', 'veere', 'kive o', 'call kari',

    # Urdu (اردو)
    'بھائی', 'کیسے ہو', 'فون کرو', 'گھر پہنچ گیا', 'bhai', 'kaise ho', 'call karo'
]

# Institutional Impersonation / Threat signals across all native languages
IMPERSONATION_TERMS = [
    # English
    'electricity power will be disconnected', 'will be disconnected', 'connection will be disconnected',
    'disconnected', 'disconnection', 'electricity connection', 'power cut', 'yono', 'pan kyc',
    'pan card blocked', 'won rs', 'lucky draw', 'processing fee', 'part-time job', 'youtube video',
    'invoice.exe', 'deactivated within 24 hours', 'verify immediately', 'sim card kyc',
    'outgoing calls will be stopped', 'pre-approved loan', 'unauthorized login attempt',
    'claim prize cheque', 'electricity officer', 'account blocked', 'debit card blocked',
    'deposit the bill', 'bill deposit', 'pay bill', 'bill payment', 'overdue bill',
    
    # Bengali (বাংলা & Banglish)
    'বিদ্যুৎ সংযোগ বিচ্ছিন্ন', 'বিদ্যুৎ লাইন কাটা হবে', 'বিদ্যুৎ বিল পরিশোধ', 'পাওয়ার কাট',
    'বিচ্ছিন্ন করা হবে', 'লাইন কাটা', 'বিদ্যুৎ সংযোগ', 'বিদ্যুৎ বিল',
    'লটারি জিতেছেন', 'পুরস্কার জিতেছেন', 'অ্যাকাউন্ট ব্লক', 'কেওয়াইসি', 'প্যান কার্ড ব্লক',
    'biddut line kata hobe', 'power cut hobe', 'lottery jitechhen', 'account block hoyeche',

    # Hindi (हिन्दी & Hinglish)
    'बिजली कनेक्शन कट जाएगा', 'बिजली बिल बाकी', 'बिजली काटी जाएगी', 'खाता ब्लॉक',
    'काट दिया जाएगा', 'काट दिया', 'बिजली कनेक्शन', 'बिजली बिल', 'बिल जमा', 'विद्युत',
    'केवाईसी अपडेट', 'लॉटरी जीती', 'इनाम जीता', 'सिम कार्ड ब्लॉक', 'कॉल बंद',
    'bijli cut jayegi', 'bijli connection', 'account block ho gaya', 'kyc update karwaye',
    'lottery jeeti hai', 'puraskar jeeta',

    # Regional Indian threats
    'वीज पुरवठा खंडित', 'மின்சாரம் துண்டிக்கப்படும்', 'విద్యుత్ సరఫరా నిలిపివేయబడుతుంది'
]

class MessageRiskPredictor:
    def __init__(self):
        self.spam_model = None
        self.vectorizer = None
        self.risk_model = None
        self.metrics = {}
        self.load_models()

    def load_models(self):
        spam_path = os.path.join(MODEL_DIR, 'spam_model.pkl')
        vec_path = os.path.join(MODEL_DIR, 'vectorizer.pkl')
        risk_path = os.path.join(MODEL_DIR, 'risk_model.pkl')
        metrics_path = os.path.join(MODEL_DIR, 'metrics.pkl')

        if not (os.path.exists(spam_path) and os.path.exists(vec_path)):
            from src.train import train_models
            train_models()

        self.spam_model = joblib.load(spam_path)
        self.vectorizer = joblib.load(vec_path)
        if os.path.exists(risk_path):
            self.risk_model = joblib.load(risk_path)
        if os.path.exists(metrics_path):
            self.metrics = joblib.load(metrics_path)

    def analyze(self, message_content, sender="Unknown Sender", subject="(No Subject)", message_type=None, user_id=None, is_explicit_trusted=False):
        """
        Executes multi-vector analysis with Known Contact Whitelist Protection
        to eliminate false positives from friends, family, and trusted colleagues.
        """
        if not message_content or not message_content.strip():
            return {
                'classification': 'HAM',
                'spam_probability': 0.0,
                'message_type': 'EMAIL',
                'is_trusted_contact': False,
                'trusted_contact_name': None,
                'urls_detected': False,
                'url_count': 0,
                'urls': [],
                'phones_detected': False,
                'phone_count': 0,
                'phones': [],
                'overall_risk': calculate_risk(0.0)
            }

        # Determine message type (Email vs SMS) if not explicitly given
        if not message_type or message_type == 'AUTO':
            if is_phone_number_sender(sender) or (subject == '(No Subject)' and len(message_content) < 300):
                message_type = 'SMS'
            else:
                message_type = 'EMAIL'

        text_lower = message_content.lower()

        # Check Whitelist / Trusted Contacts
        trusted_record = db.is_trusted_contact(sender, user_id)
        is_known_sender = is_explicit_trusted or (trusted_record is not None)
        trusted_name = trusted_record['display_name'] if trusted_record else ("Known Contact" if is_explicit_trusted else None)

        # 1. Clean and vectorize text (with native multi-language translation support)
        translated_content = translate_native_message(message_content)
        combined_text = f"{subject} {translated_content}" if subject != '(No Subject)' else translated_content
        cleaned = clean_text(combined_text)
        features = self.vectorizer.transform([cleaned])

        # 2. Raw ML Probabilities
        prediction = self.spam_model.predict(features)[0]
        probabilities = self.spam_model.predict_proba(features)[0]
        spam_prob = float(probabilities[1])

        # 3. Conversational Context vs Institutional Threat Analysis (check both original & translated)
        text_lower = message_content.lower()
        trans_lower = (translated_content or '').lower()
        has_conversational = any(re.search(rf'\b{re.escape(cm)}\b', text_lower) for cm in CONVERSATIONAL_MARKERS) or \
                             any(re.search(rf'\b{re.escape(cm)}\b', trans_lower) for cm in CONVERSATIONAL_MARKERS)
        has_impersonation = any(it in text_lower for it in IMPERSONATION_TERMS) or \
                            any(it in trans_lower for it in IMPERSONATION_TERMS)

        # 4. URL Extraction & Analysis
        extracted_urls = extract_urls(message_content)
        url_analyses = []
        highest_url_prob = 0.0
        primary_url_analysis = None
        has_malware_file = False

        for u in extracted_urls:
            u_info = analyze_url(u)
            if u_info.get('has_dangerous_ext'):
                has_malware_file = True

            u_risk = calculate_risk(spam_prob, u_info, message_content)
            u_info['risk_probability'] = u_risk['risk_probability']
            u_info['risk_level'] = u_risk['risk_level']
            u_info['risk_badge'] = u_risk['risk_badge']
            u_info['risk_type'] = u_risk['risk_type']
            u_info['possible_consequence'] = u_risk['possible_consequence']
            u_info['recommendation'] = u_risk['recommendation']

            url_analyses.append(u_info)
            if u_info['url_risk_prob'] > highest_url_prob:
                highest_url_prob = u_info['url_risk_prob']
                primary_url_analysis = u_info

        # 5. Phone Number Extraction & Analysis
        extracted_phones = extract_phone_numbers(message_content)
        phone_analyses = [analyze_embedded_phone(p, message_content) for p in extracted_phones]

        # 6. Sender Identity
        sender_analysis = analyze_phone_sender(sender, message_content) if is_phone_number_sender(sender) else None

        # 7. AUTONOMOUS DETECTION & SENSING (Self-identifies personal vs threat messages)
        is_autonomous_personal = has_conversational and not has_impersonation and not has_malware_file
        is_override_applied = False
        override_reason = None

        if is_known_sender:
            # If from a verified known contact, approve as safe unless it contains institutional impersonation or malware
            if not has_impersonation and not has_malware_file:
                spam_prob = 0.02
                prediction = 0
                is_override_applied = True
                override_reason = f"Verified Contact Whitelist: Sender '{sender}' is saved in your contacts ({trusted_name})."
            elif has_impersonation:
                override_reason = f"Account Takeover / Spoof Alert: Sender '{sender}' is in contacts, but message contains institutional fraud keywords."
        elif is_autonomous_personal:
            # The AI senses personal/peer conversational intent by itself completely autonomously
            if spam_prob > 0.15:
                spam_prob = 0.03
                prediction = 0
                is_override_applied = True
            override_reason = "Autonomous AI Sense: Detected personal conversational tone, peer context, or everyday informal communication without cyber-threat or institutional coercion cues."

        spam_prob_pct = round(spam_prob * 100, 1)
        classification = 'SPAM' if (prediction == 1 or spam_prob >= 0.50) else 'HAM'

        # 8. Overall Risk Scoring
        if (is_known_sender or is_autonomous_personal) and not has_malware_file:
            risk_label = "VERIFIED CONTACT / SAFE" if is_known_sender else "PERSONAL PEER COMMUNICATION / SAFE"
            overall_risk = {
                'risk_probability': max(1.5, round(spam_prob_pct, 1)),
                'risk_level': 'VERY LOW',
                'risk_badge': '🟢 Very Low',
                'risk_type': f'{risk_label} ({trusted_name or "Personal Chat"})',
                'possible_consequence': 'Message displays natural conversational language and interpersonal context. No phishing, vishing, or deceptive lures identified.',
                'recommendation': 'SAFE TO INTERACT. This is authentic personal communication.'
            }
        else:
            overall_risk = calculate_risk(
                spam_prob,
                primary_url_analysis,
                message_content,
                phone_analyses=phone_analyses,
                sender_analysis=sender_analysis
            )

        return {
            'sender': sender,
            'subject': subject,
            'email_content': message_content,
            'message_type': message_type,
            'is_trusted_contact': is_known_sender,
            'trusted_contact_name': trusted_name,
            'is_autonomous_personal': is_autonomous_personal,
            'is_override_applied': is_override_applied,
            'override_reason': override_reason,
            'classification': classification,
            'spam_probability': spam_prob_pct,
            'urls_detected': len(extracted_urls) > 0,
            'url_count': len(extracted_urls),
            'urls': url_analyses,
            'phones_detected': len(extracted_phones) > 0,
            'phone_count': len(extracted_phones),
            'phones': phone_analyses,
            'sender_analysis': sender_analysis,
            'overall_risk': overall_risk
        }

predictor = MessageRiskPredictor()

if __name__ == '__main__':
    # Test case: Known friend sending a message asking to call
    friend_msg = "Hey bro, call me urgently at +91 98765 43210 when you are free, need to discuss project."
    res = predictor.analyze(friend_msg, sender="+91 98765 43210", is_explicit_trusted=True)
    print("Classification:", res['classification'])
    print("Spam Prob:", res['spam_probability'], "%")
    print("Is Trusted:", res['is_trusted_contact'])
    print("Risk Level:", res['overall_risk']['risk_level'])
    print("Reason:", res['override_reason'])
