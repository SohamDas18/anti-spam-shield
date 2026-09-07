import os
import sys
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import db
from src.predict import predictor
from src.translations import t as translate_func, localize_risk_result, CLASSIFICATION_TRANSLATIONS_BN

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "sentinel-ai-cyber-threat-secret-2026")
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def get_current_authenticated_user():
    """Returns the user dict if authenticated and verified in database, else clears session and returns None."""
    if 'user_id' not in session or not session.get('user_id'):
        return None
    try:
        user = db.get_user_by_id(session['user_id'])
        if not user:
            session.clear()
            return None
        return user
    except Exception:
        session.clear()
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_authenticated_user()
        if not user:
            if request.path.startswith('/api/'):
                # Check for API Key header for headless/automated clients
                api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
                expected_key = os.getenv('API_KEY', 'sentinel-secure-api-key')
                if api_key and api_key == expected_key:
                    return f(*args, **kwargs)
                return jsonify({
                    'success': False,
                    'error': 'Authentication required. Please log in or provide a valid API Key.',
                    'authenticated': False
                }), 401
            flash('Access restricted. Please log in or register to access the Sentinel threat analysis platform.', 'warning')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_headers(response):
    """Enforce strict no-cache headers so browser Back button and history do not expose protected dashboard after logout."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

@app.context_processor
def inject_global():
    user = get_current_authenticated_user()
    cur_lang = session.get('lang', 'en')
    return {
        'current_user': user,
        'db_engine': db.engine.upper(),
        'db_status': db.status_msg,
        'now': datetime.now(),
        'current_lang': cur_lang,
        't': lambda key, default=None: translate_func(key, lang=session.get('lang', 'en'), default=default)
    }

@app.route('/set-language/<lang>')
def set_language(lang):
    """Sets the active UI and report language (English or Bengali / বাংলা)."""
    if lang in ['en', 'bn']:
        session['lang'] = lang
    ref = request.referrer
    if ref and (request.host in ref):
        return redirect(ref)
    if get_current_authenticated_user():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ----------------- AUTHENTICATION ROUTES ----------------- #

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user account with full backend validation and password hashing."""
    if get_current_authenticated_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # 1. Required fields
        if not name or not email or not password or not confirm_password:
            flash('All registration fields are required.', 'danger')
            return render_template('register.html', name=name, email=email)

        # 2. Name validation
        if len(name) < 2 or len(name) > 100:
            flash('Full Name must be between 2 and 100 characters.', 'warning')
            return render_template('register.html', name=name, email=email)

        # 3. Email format validation
        if not EMAIL_REGEX.match(email):
            flash('Please enter a valid email address (e.g. analyst@sentinel.shield).', 'warning')
            return render_template('register.html', name=name, email=email)

        # 4. Password security requirements
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
            return render_template('register.html', name=name, email=email)

        # 5. Password confirmation
        if password != confirm_password:
            flash('Password and Confirm Password do not match. Please verify.', 'warning')
            return render_template('register.html', name=name, email=email)

        # 6. Duplicate email check
        existing = db.get_user_by_email(email)
        if existing:
            flash('An account with this email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))

        # Secure password hashing (Werkzeug PBKDF2/scrypt)
        pwd_hash = generate_password_hash(password)
        db.create_user(name, email, pwd_hash)

        flash('Account created successfully! Please sign in with your credentials.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate user with email and securely hashed password."""
    if get_current_authenticated_user():
        return redirect(url_for('dashboard'))

    next_url = request.args.get('next') or request.form.get('next')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please enter both your email address and password.', 'warning')
            return render_template('login.html', email=email, next_url=next_url)

        user = db.get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            flash(f'Welcome back, {user["name"]}! Sentinel Threat Analysis Console unlocked.', 'success')

            # Safe redirection against open redirect attacks
            if next_url and next_url.startswith('/') and not next_url.startswith('//') and next_url not in ['/login', '/register', '/logout']:
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please verify your credentials.', 'danger')
            return render_template('login.html', email=email, next_url=next_url)

    return render_template('login.html', next_url=next_url)

@app.route('/logout')
def logout():
    """Securely clears session, expires cookies, and redirects to the Login page."""
    session.clear()
    flash('You have been securely logged out of Sentinel.', 'info')
    resp = redirect(url_for('login'))
    resp.set_cookie(app.config.get('SESSION_COOKIE_NAME', 'session'), '', expires=0, max_age=0)
    return resp

# ----------------- TRUSTED CONTACTS (WHITELIST) ROUTES ----------------- #

@app.route('/contacts')
@login_required
def contacts_page():
    """Manage known persons/contacts whitelist to eliminate false positives."""
    user_id = session.get('user_id') if 'user_id' in session else None
    contacts = db.get_trusted_contacts(user_id=user_id)
    return render_template('contacts.html', contacts=contacts)

@app.route('/contacts/add', methods=['POST'])
@login_required
def add_contact():
    name = request.form.get('display_name', '').strip()
    identifier = request.form.get('contact_identifier', '').strip()
    notes = request.form.get('notes', '').strip()
    user_id = session.get('user_id') if 'user_id' in session else None

    if not name or not identifier:
        flash('Name and Phone/Email are required.', 'warning')
        return redirect(url_for('contacts_page'))

    contact_type = 'EMAIL' if '@' in identifier else 'PHONE'
    db.add_trusted_contact(identifier, name, contact_type=contact_type, user_id=user_id, notes=notes)
    flash(f'Added {name} ({identifier}) to your Trusted Contacts. Messages from this sender will now be recognized as safe!', 'success')
    return redirect(url_for('contacts_page'))

@app.route('/contacts/delete/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    user_id = session.get('user_id') if 'user_id' in session else None
    db.delete_trusted_contact(contact_id, user_id=user_id)
    flash('Contact removed from trusted whitelist.', 'info')
    return redirect(url_for('contacts_page'))

@app.route('/api/mark-safe', methods=['POST'])
@login_required
def api_mark_safe():
    """1-Click button from the Result page to resolve false positive and add sender to whitelist."""
    data = request.get_json() or {}
    email_id = data.get('email_id')
    contact_name = data.get('contact_name', 'Known Contact')

    if not email_id:
        return jsonify({'success': False, 'error': 'Missing email_id'}), 400

    success = db.mark_email_as_safe(email_id, contact_name=contact_name)
    return jsonify({'success': success})

# ----------------- MAIN CORE ROUTES ----------------- #

@app.route('/')
def index():
    """Root website URL.
    Checks whether the user is authenticated:
    - If authenticated: redirect to /dashboard
    - If NOT authenticated: redirect to /login
    """
    user = get_current_authenticated_user()
    if user:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/analyzer')
@login_required
def analyzer():
    """Dedicated alias for the Sentinel Threat Analyzer Studio."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@login_required
def analyze_email():
    """Processes Email or SMS, runs ML & Phone/URL analysis, and stores in database."""
    message_type = request.form.get('message_type', 'AUTO').strip()
    sender = request.form.get('sender', '').strip()
    subject = request.form.get('subject', '').strip()
    email_content = request.form.get('email_content', '').strip()
    is_explicit_trusted = (request.form.get('is_trusted_sender') == '1')

    if not email_content:
        flash('Please enter email or SMS message content to analyze.', 'warning')
        return redirect(url_for('index'))

    if message_type == 'SMS':
        sender = sender or '+91-UNKNOWN'
        subject = subject or '(SMS Alert)'
    else:
        sender = sender or 'Unknown Sender'
        subject = subject or '(No Subject)'

    user_id = session.get('user_id', None)

    # If user explicitly checked 'Sender is a known person', save to trusted contacts
    if is_explicit_trusted:
        c_type = 'EMAIL' if '@' in sender else 'PHONE'
        db.add_trusted_contact(sender, "Known Person (Self-Declared)", contact_type=c_type, user_id=user_id)

    # Run unified prediction pipeline with whitelist check
    result = predictor.analyze(
        email_content,
        sender=sender,
        subject=subject,
        message_type=message_type,
        user_id=user_id,
        is_explicit_trusted=is_explicit_trusted
    )

    # Persist in MySQL / SQLite
    email_id = db.save_analysis(
        user_id=user_id,
        sender=sender,
        subject=subject,
        email_content=email_content,
        classification=result['classification'],
        spam_probability=result['spam_probability'],
        url_analyses=result['urls'],
        phone_analyses=result['phones'],
        message_type=result['message_type'],
        is_trusted=1 if result['is_trusted_contact'] else 0
    )

    return redirect(url_for('view_result', email_id=email_id))

@app.route('/result/<int:email_id>')
@login_required
def view_result(email_id):
    """Displays comprehensive Security Report Card with URLs, Phone Numbers, and Trusted Status."""
    email_data = db.get_email_details(email_id)
    if not email_data:
        flash('Report not found.', 'danger')
        return redirect(url_for('index'))

    urls = email_data.get('urls', [])
    phones = email_data.get('phones', [])
    is_trusted = bool(email_data.get('is_trusted_sender', 0)) or bool(db.is_trusted_contact(email_data['sender']))

    top_url = None
    if urls:
        urls = sorted(urls, key=lambda x: float(x.get('risk_probability', 0)), reverse=True)
        top_url = {
            'url_risk_prob': float(urls[0]['risk_probability']) / 100.0,
            'matched_keywords': [urls[0]['risk_type']],
            'has_dangerous_ext': '.exe' in urls[0]['url'] or 'MALWARE' in urls[0]['risk_type']
        }

    from src.risk_analyzer import calculate_risk
    from src.phone_analyzer import analyze_phone_sender
    from src.predict import CONVERSATIONAL_MARKERS, IMPERSONATION_TERMS
    import re

    text_lower = (email_data.get('email_content') or '').lower()
    has_conversational = any(re.search(rf'\b{re.escape(cm)}\b', text_lower) for cm in CONVERSATIONAL_MARKERS)
    has_impersonation = any(it in text_lower for it in IMPERSONATION_TERMS)
    is_autonomous_personal = has_conversational and not has_impersonation

    if is_trusted:
        overall_risk = {
            'risk_probability': 2.0,
            'risk_level': 'VERY LOW',
            'risk_badge': '🟢 Very Low',
            'risk_type': 'VERIFIED KNOWN CONTACT / SAFE',
            'possible_consequence': 'Message originated from a known contact on your verified whitelist. No security threats detected.',
            'recommendation': 'SAFE TO INTERACT. This contact is recognized as legitimate.'
        }
        sender_analysis = None
    elif is_autonomous_personal and email_data['classification'] == 'HAM':
        overall_risk = {
            'risk_probability': max(1.5, round(float(email_data['spam_probability']), 1)),
            'risk_level': 'VERY LOW',
            'risk_badge': '🟢 Very Low',
            'risk_type': 'PERSONAL COMMUNICATION / SAFE (AI Auto-Sensed)',
            'possible_consequence': 'Autonomous AI detection recognized natural human conversational language and everyday peer interaction. No cyber threats found.',
            'recommendation': 'SAFE TO INTERACT. The AI senses this as authentic personal communication.'
        }
        sender_analysis = analyze_phone_sender(email_data['sender'], email_data['email_content'])
    else:
        sender_analysis = analyze_phone_sender(email_data['sender'], email_data['email_content'])
        overall_risk = calculate_risk(
            float(email_data['spam_probability']) / 100.0,
            top_url,
            email_data['email_content'],
            phone_analyses=phones,
            sender_analysis=sender_analysis
        )
    from src.geo_locator import locate_sender, locate_url_hosts, locate_callback_phones, build_interactive_map_payload

    sender_geo = locate_sender(
        email_data.get('sender'),
        email_data.get('message_type'),
        text_content=email_data.get('email_content', ''),
        user_id=session.get('user_id')
    )
    url_geos = locate_url_hosts(urls)
    phone_geos = locate_callback_phones(phones, text_content=email_data.get('email_content', ''))
    map_pins = build_interactive_map_payload(sender_geo, url_geos=url_geos, phone_geos=phone_geos)

    cur_lang = session.get('lang', 'en')
    if cur_lang == 'bn':
        overall_risk = localize_risk_result(overall_risk, lang='bn')

    return render_template(
        'result.html',
        email=email_data,
        urls=urls,
        phones=phones,
        sender_analysis=sender_analysis,
        overall_risk=overall_risk,
        is_autonomous_personal=is_autonomous_personal,
        sender_geo=sender_geo,
        url_geos=url_geos,
        phone_geos=phone_geos,
        map_pins=map_pins
    )

@app.route('/history')
@login_required
def history():
    """Audit ledger of all analyzed emails and SMS messages."""
    user_id = session.get('user_id') if 'user_id' in session else None
    records = db.get_history(user_id=user_id, limit=100)
    return render_template('history.html', records=records)

@app.route('/dashboard')
@login_required
def dashboard():
    """Executive security dashboard with visual KPIs and charts."""
    user_id = session.get('user_id') if 'user_id' in session else None
    metrics = db.get_dashboard_metrics(user_id=user_id)
    return render_template('dashboard.html', metrics=metrics, model_metrics=predictor.metrics)

# ----------------- REST API ----------------- #

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    data = request.get_json() or {}
    message_type = data.get('message_type', 'AUTO')
    sender = data.get('sender', '+91 9876543210' if message_type == 'SMS' else 'api@client.com')
    subject = data.get('subject', '(SMS Message)' if message_type == 'SMS' else 'API Request')
    content = data.get('email_content', '')
    is_trusted = data.get('is_trusted', False)

    if not content:
        return jsonify({'success': False, 'error': 'Missing email_content'}), 400

    user_id = session.get('user_id', None)
    result = predictor.analyze(content, sender=sender, subject=subject, message_type=message_type, is_explicit_trusted=is_trusted, user_id=user_id)
    email_id = db.save_analysis(
        user_id=user_id,
        sender=sender,
        subject=subject,
        email_content=content,
        classification=result['classification'],
        spam_probability=result['spam_probability'],
        url_analyses=result['urls'],
        phone_analyses=result['phones'],
        message_type=result['message_type'],
        is_trusted=1 if result['is_trusted_contact'] else 0
    )
    result['email_id'] = email_id
    result['success'] = True
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    print(f"Spam Mail & SMS Phone Threat Analysis System running on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)
