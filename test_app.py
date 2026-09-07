import os
import sys
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from db import db
from src.preprocessing import clean_text
from src.url_analyzer import extract_urls, analyze_url
from src.phone_analyzer import extract_phone_numbers, analyze_embedded_phone, analyze_phone_sender
from src.risk_analyzer import calculate_risk
from src.predict import predictor

class TestSpamMailRiskSystem(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_01_text_preprocessing(self):
        raw = "CONGRATULATIONS!!! You WON $1000 in lottery. Click HERE: https://example.com/prize"
        cleaned = clean_text(raw)
        self.assertNotIn("https://", cleaned)
        self.assertIn("congratul", cleaned)

    def test_02_url_extraction_and_analysis(self):
        email_text = "Please verify your account at https://account-verify-portal.bank.secure.com/login.php and download https://example.com/update.exe"
        urls = extract_urls(email_text)
        self.assertEqual(len(urls), 2)
        
        info_exe = analyze_url(urls[1])
        self.assertTrue(info_exe['has_dangerous_ext'])
        self.assertEqual(info_exe['matched_extension'], '.exe')

        info_phish = analyze_url(urls[0])
        self.assertTrue(len(info_phish['matched_keywords']) > 0)

    def test_03_phone_number_extraction_and_analysis(self):
        sms_text = "Electricity disconnected tonight! Call officer at +91-8877665544 or WhatsApp +1 (555) 349-2011"
        phones = extract_phone_numbers(sms_text)
        self.assertEqual(len(phones), 2)

        info = analyze_embedded_phone(phones[0], sms_text)
        self.assertTrue(info['has_callback_lure'])
        self.assertEqual(info['risk_level'], 'HIGH')

        sender_eval = analyze_phone_sender("+91 98765 43210", sms_text)
        self.assertEqual(sender_eval['sender_risk'], 'CRITICAL')

    def test_04_legitimate_email_prediction(self):
        ham_text = "Hi Team, the project status meeting is confirmed for tomorrow at 10 AM. See you there."
        res = predictor.analyze(ham_text)
        self.assertEqual(res['classification'], 'HAM')
        self.assertLess(res['spam_probability'], 40.0)
        self.assertIn(res['overall_risk']['risk_level'], ['VERY LOW', 'LOW'])

    def test_05_phishing_email_prediction(self):
        phish_text = "URGENT! Your account has been temporarily suspended. Verify your account immediately: https://account-security-verification-example.com/login.php"
        res = predictor.analyze(phish_text)
        self.assertEqual(res['classification'], 'SPAM')
        self.assertGreater(res['spam_probability'], 60.0)
        self.assertIn(res['overall_risk']['risk_level'], ['HIGH', 'CRITICAL'])

    def test_06_sms_power_cut_smishing_prediction(self):
        sms = "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at +91-8877665544."
        res = predictor.analyze(sms, sender="+91 88776 65544", message_type="SMS")
        self.assertEqual(res['classification'], 'SPAM')
        self.assertEqual(res['message_type'], 'SMS')
        self.assertTrue(res['phones_detected'])
        self.assertIn(res['overall_risk']['risk_type'], ['UTILITY DISCONNECTION SCAM / VISHING', 'VISHING / CALLBACK FRAUD'])
        self.assertIn("DO NOT CALL", res['overall_risk']['recommendation'])

    def test_07_known_person_whitelist_protection(self):
        # Known friend asking to call urgently with a phone number
        friend_msg = "Hey bro, call me urgently at +91 98765 43210 when you are free, need to ask about college project."
        # Add to trusted contacts
        db.add_trusted_contact("+91 98765 43210", "Rahul Friend", contact_type="PHONE")

        res = predictor.analyze(friend_msg, sender="+91 98765 43210", message_type="SMS")
        # Must be classified as HAM (not Spam) because sender is in Trusted Contacts whitelist!
        self.assertEqual(res['classification'], 'HAM')
        self.assertTrue(res['is_trusted_contact'])
        self.assertLessEqual(res['spam_probability'], 5.0)
        self.assertEqual(res['overall_risk']['risk_level'], 'VERY LOW')

    def test_08_authentication_and_protected_routes(self):
        # 1. Unauthenticated users should be redirected (302) from protected routes to /login
        for protected_path in ['/', '/analyzer', '/dashboard', '/history', '/contacts']:
            response = self.app.get(protected_path)
            self.assertEqual(response.status_code, 302, f"Unauthenticated access to {protected_path} should redirect to /login")
            self.assertIn('/login', response.headers.get('Location', ''))

        # 2. Login and Register pages must be publicly accessible (200)
        for public_path in ['/login', '/register']:
            response = self.app.get(public_path)
            self.assertEqual(response.status_code, 200, f"Public route {public_path} failed")

        # 3. Unauthenticated API request should receive 401 Unauthorized
        api_unauth = self.app.post('/api/analyze', json={'email_content': 'Test message'})
        self.assertEqual(api_unauth.status_code, 401)

        # 4. User Registration Flow
        test_email = "security.tester@sentinel.shield"
        reg_res = self.app.post('/register', data={
            'name': 'Sentinel Analyst',
            'email': test_email,
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123'
        }, follow_redirects=False)
        self.assertEqual(reg_res.status_code, 302)
        self.assertIn('/login', reg_res.headers.get('Location', ''))

        # 5. User Login Flow
        login_res = self.app.post('/login', data={
            'email': test_email,
            'password': 'SecurePassword123'
        }, follow_redirects=False)
        self.assertEqual(login_res.status_code, 302)

        # 6. Authenticated Session Access to Protected Routes
        with self.app.session_transaction() as sess:
            user = db.get_user_by_email(test_email)
            self.assertIsNotNone(user)
            sess['user_id'] = user['id']
            sess['user_name'] = user['name']
            sess['user_email'] = user['email']

        for protected_path in ['/', '/analyzer', '/dashboard', '/history', '/contacts']:
            auth_response = self.app.get(protected_path)
            self.assertEqual(auth_response.status_code, 200, f"Authenticated access to {protected_path} failed")

        # 7. Authenticated API Access
        api_auth = self.app.post('/api/analyze', json={
            'message_type': 'SMS',
            'sender': '+91 9876543210',
            'email_content': 'Hey bro, see you tomorrow at 5 PM for dinner.'
        })
        self.assertEqual(api_auth.status_code, 200)
        data = api_auth.get_json()
        self.assertTrue(data['success'])

        # 8. Logout Flow
        logout_res = self.app.get('/logout')
        self.assertEqual(logout_res.status_code, 302)
        self.assertIn('/login', logout_res.headers.get('Location', ''))
    def test_09_autonomous_personal_sensing_without_whitelist(self):
        """Tests that the AI autonomously senses friend/family messages WITHOUT any manual whitelist or user hints."""
        personal_samples = [
            "Can you transfer money for movie tickets? My UPI is not working",
            "I lost my phone, this is my new temporary number 9812345678, save it",
            "Check this out: https://youtube.com/watch?v=12345",
            "Call me urgently, it is important.",
            "Hey, can you send me 500 rs on GPay? Will return it tomorrow.",
            "Mom said dinner is ready, come home soon"
        ]
        for sample in personal_samples:
            res = predictor.analyze(sample, sender="Unknown Sender", is_explicit_trusted=False)
            self.assertEqual(res['classification'], 'HAM', f"Failed to autonomously sense HAM on: '{sample}'")
            self.assertEqual(res['overall_risk']['risk_level'], 'VERY LOW', f"Risk not VERY LOW on: '{sample}'")
    def test_10_auth_edge_cases(self):
        # A. Registration Validation: Mismatched Passwords
        res_mismatch = self.app.post('/register', data={
            'name': 'Test User',
            'email': 'mismatch@sentinel.shield',
            'password': 'Password123',
            'confirm_password': 'DifferentPassword456'
        })
        self.assertEqual(res_mismatch.status_code, 200) # Re-renders register page

        # B. Registration Validation: Short Password (< 6 chars)
        res_short = self.app.post('/register', data={
            'name': 'Test User',
            'email': 'short@sentinel.shield',
            'password': '123',
            'confirm_password': '123'
        })
        self.assertEqual(res_short.status_code, 200)

        # C. Registration Validation: Invalid Email Format
        res_bad_email = self.app.post('/register', data={
            'name': 'Test User',
            'email': 'invalid-email-format',
            'password': 'Password123',
            'confirm_password': 'Password123'
        })
        self.assertEqual(res_bad_email.status_code, 200)

        # D. Login Validation: Invalid Credentials
        res_bad_login = self.app.post('/login', data={
            'email': 'nonexistent@sentinel.shield',
            'password': 'WrongPassword123'
        })
        self.assertEqual(res_bad_login.status_code, 200)

        # E. Login with next URL redirection
        test_email = "redirect.test@sentinel.shield"
        self.app.post('/register', data={
            'name': 'Redirect User',
            'email': test_email,
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123'
        })
        res_login_next = self.app.post('/login?next=/dashboard', data={
            'email': test_email,
            'password': 'SecurePassword123'
        }, follow_redirects=False)
        self.assertEqual(res_login_next.status_code, 302)
        self.assertEqual(res_login_next.headers.get('Location'), '/dashboard')

        # F. Authenticated user visiting /login or /register should be redirected to /
        with self.app.session_transaction() as sess:
            u = db.get_user_by_email(test_email)
            sess['user_id'] = u['id']
            sess['user_name'] = u['name']

        res_auth_login = self.app.get('/login')
        self.assertEqual(res_auth_login.status_code, 302)

        res_auth_register = self.app.get('/register')
        self.assertEqual(res_auth_register.status_code, 302)

if __name__ == '__main__':
    unittest.main()
