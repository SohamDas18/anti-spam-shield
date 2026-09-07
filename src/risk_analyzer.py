def calculate_risk(spam_probability, url_analysis=None, email_text="", phone_analyses=None, sender_analysis=None):
    """
    Combines text spam confidence, URL indicators, and phone number/SMS indicators
    to determine risk probability, risk level, risk type, possible consequence,
    and security recommendations.
    """
    text_lower = email_text.lower() if email_text else ""
    has_url = url_analysis is not None
    has_phones = phone_analyses is not None and len(phone_analyses) > 0
    is_phone_sender = sender_analysis is not None and sender_analysis.get('is_phone_sender', False)

    # Base component scores
    base_spam_weight = 0.40
    url_weight = 0.35 if has_url else 0.0
    phone_weight = 0.25 if (has_phones or is_phone_sender) else 0.0

    # Normalize weights
    total_weights = base_spam_weight + url_weight + phone_weight
    if total_weights > 0:
        base_spam_weight /= total_weights
        url_weight /= total_weights
        phone_weight /= total_weights

    # URL component
    url_score = url_analysis.get('url_risk_prob', 0.1) if has_url else 0.0

    # Phone component
    phone_score = 0.1
    if has_phones:
        max_phone_prob = max((p.get('risk_probability', 10) / 100.0) for p in phone_analyses)
        phone_score = max_phone_prob
    if sender_analysis and sender_analysis.get('score'):
        phone_score = max(phone_score, sender_analysis['score'])

    # Blended risk
    combined_prob = (spam_probability * base_spam_weight) + (url_score * url_weight) + (phone_score * phone_weight)
    
    # Smishing amplifier: if urgent bank/electricity message comes with a phone number or link, amplify risk
    if ('power' in text_lower or 'electricity' in text_lower or 'yono' in text_lower or 'kyc' in text_lower) and (has_phones or has_url):
        combined_prob = max(combined_prob, 0.88)

    risk_prob = min(0.99, max(0.01, combined_prob))
    risk_prob_pct = round(risk_prob * 100, 1)

    # 1. Determine Risk Level
    if risk_prob_pct >= 80.0:
        risk_level = "CRITICAL"
        risk_badge = "🔴 Critical"
    elif risk_prob_pct >= 60.0:
        risk_level = "HIGH"
        risk_badge = "🟠 High"
    elif risk_prob_pct >= 40.0:
        risk_level = "MEDIUM"
        risk_badge = "🟡 Medium"
    elif risk_prob_pct >= 20.0:
        risk_level = "LOW"
        risk_badge = "🟢 Low"
    else:
        risk_level = "VERY LOW"
        risk_badge = "🟢 Very Low"

    # 2. Determine Risk Type, Consequence, Recommendation
    risk_type = "VERY LOW / LEGITIMATE"
    possible_consequence = "No significant security threats or deceptive patterns were identified."
    recommendation = "Message appears legitimate. Standard digital safety precautions apply."

    if risk_level in ["CRITICAL", "HIGH", "MEDIUM"]:

        # Phone-specific Threat 1: Fake Electricity / Bill Disconnection Scam
        if any(w in text_lower for w in ['electricity', 'power cut', 'disconnected', 'power will be disconnected', 'officer']):
            risk_type = "UTILITY DISCONNECTION SCAM / VISHING"
            possible_consequence = "Scammers pose as power officials to intimidate victims into calling a fake officer number and transferring fraudulent payments."
            recommendation = "DO NOT CALL THE NUMBER. Official utility providers never warn of power cuts via personal mobile numbers or require immediate money transfers."

        # Phone-specific Threat 2: Bank KYC / YONO SMS Smishing
        elif any(w in text_lower for w in ['yono', 'pan update', 'kyc pending', 'account blocked', 'debit card blocked']):
            risk_type = "SMISHING (SMS PHISHING) / KYC FRAUD"
            possible_consequence = "The SMS attempts to coerce you into clicking a spoofed banking link or calling an unauthorized mobile number to steal banking PINs and OTPs."
            recommendation = "DO NOT CLICK OR CALL. Indian and international banks will never request KYC or PAN updates via SMS links or standard mobile numbers."

        # Phone-specific Threat 3: Work-From-Home / Telegram / WhatsApp Job Scam
        elif any(w in text_lower for w in ['earn', 'daily', 'part time job', 'youtube like', 'like videos', 'telegram', 'whatsapp']):
            risk_type = "TASK / JOB ADVANCE SCAM"
            possible_consequence = "Victims are guided into WhatsApp/Telegram chat groups with promises of quick profits, then pressured into investing increasing sums of money."
            recommendation = "DO NOT CONTACT ON WHATSAPP. Legitimate employers never recruit via unsolicited bulk SMS promising payments for social media likes."

        # Phone-specific Threat 4: Callback / Vishing Trap
        elif has_phones and any(w in text_lower for w in ['call immediately', 'dial now', 'helpline', 'contact manager', 'executive']):
            risk_type = "VISHING / CALLBACK FRAUD"
            possible_consequence = "Calling the embedded phone number connects to a social engineer who will attempt to trick you into revealing confidential credentials."
            recommendation = "DO NOT CALL THE PHONE NUMBER. Verify customer care numbers solely from official physical cards or the company's verified domain."

        # Threat 5: Malware
        elif has_url and url_analysis.get('has_dangerous_ext'):
            risk_type = "MALWARE"
            possible_consequence = "The link attempts to deliver a potentially malicious executable or script that could compromise your device."
            recommendation = "DO NOT DOWNLOAD THE FILE. Immediately delete this message and run an antivirus scan."

        # Threat 6: Credential Theft
        elif has_url and any(kw in url_analysis.get('matched_keywords', []) for kw in ['login', 'password', 'auth', 'signin']):
            risk_type = "CREDENTIAL THEFT"
            possible_consequence = "The link directs to a deceptive authentication interface designed to harvest your login credentials and passwords."
            recommendation = "DO NOT ENTER CREDENTIALS. Never input passwords or usernames into links originating from unsolicited messages."

        # Threat 7: Phishing
        elif has_url and any(kw in url_analysis.get('matched_keywords', []) for kw in ['verify', 'verification', 'account', 'security', 'update']):
            risk_type = "PHISHING"
            possible_consequence = "The link may lead to a spoofed organizational website aimed at extracting personal identification and account details."
            recommendation = "DO NOT CLICK THE LINK. Navigate to the service's official website directly via your browser."

        # Threat 8: Financial Fraud / Prize
        elif any(w in text_lower for w in ['won', 'lottery', 'prize', 'reward', 'fee', 'processing fee', 'refund', 'tax refund', 'crore', 'lakh']):
            risk_type = "FINANCIAL FRAUD / LOTTERY SCAM"
            possible_consequence = "The sender attempts to defraud you into paying advance fees or surrendering sensitive bank account details."
            recommendation = "DO NOT SEND MONEY OR CALL. No legitimate entity asks for upfront fees to release lottery funds."

        else:
            if has_url:
                risk_type = "SUSPICIOUS URL / PHISHING"
                possible_consequence = "The embedded link displays multiple unverified indicators that may lead to malicious web content."
                recommendation = "AVOID INTERACTION. Delete the message and block the sender."
            elif has_phones:
                risk_type = "UNSOLICITED TELEMARKETING / SCAM"
                possible_consequence = "Potential phone-based marketing scam or spoofed communication."
                recommendation = "DO NOT REPLY OR CALL. Block the phone number."
            else:
                risk_type = "UNSOLICITED SPAM"
                possible_consequence = "Unwanted commercial or manipulative bulk message."
                recommendation = "MARK AS SPAM. Do not reply to unsolicited messages."

    return {
        'risk_probability': risk_prob_pct,
        'risk_level': risk_level,
        'risk_badge': risk_badge,
        'risk_type': risk_type,
        'possible_consequence': possible_consequence,
        'recommendation': recommendation
    }
