import os
import re
import json
import logging
import sqlite3
import pymysql
import pymysql.cursors
from dotenv import load_dotenv

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

load_dotenv()
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "spam_detection")

SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spam_detection.db")

def normalize_identifier(identifier):
    """Normalizes phone numbers to their last 10 digits or emails to lowercase."""
    if not identifier:
        return ""
    identifier = identifier.strip().lower()
    if '@' in identifier:
        return identifier
    # Extract only digits for phone numbers
    digits = re.sub(r'\D', '', identifier)
    if len(digits) >= 10:
        return digits[-10:]
    return digits

class Database:
    def __init__(self):
        self.engine = "sqlite"
        self.status_msg = ""
        self.pg_url = None
        self.init_connection()

    def init_connection(self):
        # 1. First priority: Persistent Cloud PostgreSQL (Render Free Database / Supabase)
        if DATABASE_URL and PSYCOPG2_AVAILABLE:
            try:
                pg_url = DATABASE_URL
                if pg_url.startswith("postgres://"):
                    pg_url = pg_url.replace("postgres://", "postgresql://", 1)
                conn = psycopg2.connect(pg_url, connect_timeout=4)
                conn.close()
                self.engine = "postgres"
                self.pg_url = pg_url
                self.status_msg = "Connected to Persistent Cloud PostgreSQL (Permanent Storage)"
                self._create_postgres_tables()
                return
            except Exception as e:
                logger.warning(f"PostgreSQL connection failed, trying MySQL/SQLite fallback: {e}")

        # 2. Second priority: MySQL
        try:
            conn = pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                connect_timeout=2
            )
            with conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
            conn.close()

            conn = pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=2
            )
            conn.close()
            self.engine = "mysql"
            self.status_msg = f"Connected to MySQL ({DB_HOST}:{DB_PORT}/{DB_NAME})"
            self._create_mysql_tables()
            return
        except Exception as e:
            # 3. Third priority: SQLite fallback with auto-seeded persistent admin accounts
            self.engine = "sqlite"
            self.status_msg = f"Using SQLite ({os.path.basename(SQLITE_PATH)})"
            self._create_sqlite_tables()

    def get_connection(self):
        if self.engine == "postgres":
            return psycopg2.connect(self.pg_url)
        elif self.engine == "mysql":
            return pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
        else:
            conn = sqlite3.connect(SQLITE_PATH)
            conn.row_factory = sqlite3.Row
            return conn

    def _create_mysql_tables(self):
        queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NULL,
                message_type VARCHAR(20) DEFAULT 'EMAIL',
                sender VARCHAR(255),
                subject VARCHAR(500),
                email_content TEXT NOT NULL,
                classification VARCHAR(20) NOT NULL,
                spam_probability DECIMAL(5, 2) NOT NULL,
                phone_numbers TEXT,
                is_trusted_sender TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user (user_id),
                INDEX idx_msg_type (message_type),
                INDEX idx_class (classification)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS url_analysis (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email_id INT NOT NULL,
                url TEXT NOT NULL,
                risk_probability DECIMAL(5, 2) NOT NULL,
                risk_level VARCHAR(20) NOT NULL,
                risk_type VARCHAR(100) NOT NULL,
                possible_consequence TEXT,
                recommendation TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS phone_analysis (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email_id INT NOT NULL,
                phone_number VARCHAR(50) NOT NULL,
                country VARCHAR(100),
                number_type VARCHAR(50),
                risk_probability DECIMAL(5, 2) NOT NULL,
                risk_level VARCHAR(20) NOT NULL,
                flags TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_phone_email (email_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS trusted_contacts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NULL,
                contact_identifier VARCHAR(255) NOT NULL,
                display_name VARCHAR(100) NOT NULL,
                contact_type VARCHAR(20) DEFAULT 'PHONE',
                notes VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_contact (contact_identifier)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        ]
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                for q in queries:
                    cursor.execute(q)
            conn.commit()
        finally:
            conn.close()

    def _create_postgres_tables(self):
        queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS emails (
                id SERIAL PRIMARY KEY,
                user_id INT NULL,
                message_type VARCHAR(20) DEFAULT 'EMAIL',
                sender VARCHAR(255),
                subject VARCHAR(500),
                email_content TEXT NOT NULL,
                classification VARCHAR(20) NOT NULL,
                spam_probability DECIMAL(5, 2) NOT NULL,
                phone_numbers TEXT,
                is_trusted_sender INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS url_analysis (
                id SERIAL PRIMARY KEY,
                email_id INT NOT NULL,
                url TEXT NOT NULL,
                risk_probability DECIMAL(5, 2) NOT NULL,
                risk_level VARCHAR(20) NOT NULL,
                risk_type VARCHAR(100) NOT NULL,
                possible_consequence TEXT,
                recommendation TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phone_analysis (
                id SERIAL PRIMARY KEY,
                email_id INT NOT NULL,
                phone_number VARCHAR(50) NOT NULL,
                country VARCHAR(100),
                number_type VARCHAR(50),
                risk_probability DECIMAL(5, 2) NOT NULL,
                risk_level VARCHAR(20) NOT NULL,
                flags TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS trusted_contacts (
                id SERIAL PRIMARY KEY,
                user_id INT NULL,
                contact_identifier VARCHAR(255) NOT NULL,
                display_name VARCHAR(100) NOT NULL,
                contact_type VARCHAR(20) DEFAULT 'PHONE',
                notes VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        ]
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                for q in queries:
                    cursor.execute(q)
                for u_name, u_email in [
                    ("Soham Das", "sohamdas9231@gmail.com"),
                    ("Soham Das", "sohamdas544@gmail.com")
                ]:
                    cursor.execute("""
                        INSERT INTO users (name, email, password_hash)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (email) DO NOTHING;
                    """, (u_name, u_email, "scrypt:32768:8:1$nzWTRVT3C4Lwh3pN$a5e7d1f2072ccbcce645316973cd4e7ec13171c1619350259a986cece039f4f6246ce4d89e9a801d08043456f30f82474cb1c88068bdbdc4a28a9e1f1258659a"))
            conn.commit()
        finally:
            conn.close()

    def _create_sqlite_tables(self):
        queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NULL,
                message_type TEXT DEFAULT 'EMAIL',
                sender TEXT,
                subject TEXT,
                email_content TEXT NOT NULL,
                classification TEXT NOT NULL,
                spam_probability REAL NOT NULL,
                phone_numbers TEXT,
                is_trusted_sender INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS url_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                risk_probability REAL NOT NULL,
                risk_level TEXT NOT NULL,
                risk_type TEXT NOT NULL,
                possible_consequence TEXT,
                recommendation TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phone_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                phone_number TEXT NOT NULL,
                country TEXT,
                number_type TEXT,
                risk_probability REAL NOT NULL,
                risk_level TEXT NOT NULL,
                flags TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS trusted_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NULL,
                contact_identifier TEXT NOT NULL,
                display_name TEXT NOT NULL,
                contact_type TEXT DEFAULT 'PHONE',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        ]
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for q in queries:
                cursor.execute(q)
            # Run migrations for existing databases
            for col_query in [
                "ALTER TABLE emails ADD COLUMN message_type TEXT DEFAULT 'EMAIL';",
                "ALTER TABLE emails ADD COLUMN phone_numbers TEXT;",
                "ALTER TABLE emails ADD COLUMN is_trusted_sender INTEGER DEFAULT 0;"
            ]:
                try:
                    cursor.execute(col_query)
                except Exception:
                    pass

            # Ensure essential admin accounts always exist in SQLite even on fresh container clone
            for u_name, u_email in [
                ("Soham Das", "sohamdas9231@gmail.com"),
                ("Soham Das", "sohamdas544@gmail.com")
            ]:
                cursor.execute("""
                    INSERT OR IGNORE INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)
                """, (u_name, u_email, "scrypt:32768:8:1$nzWTRVT3C4Lwh3pN$a5e7d1f2072ccbcce645316973cd4e7ec13171c1619350259a986cece039f4f6246ce4d89e9a801d08043456f30f82474cb1c88068bdbdc4a28a9e1f1258659a"))

            conn.commit()
        finally:
            conn.close()

    def execute_query(self, query, params=None, fetchone=False, fetchall=False, commit=False):
        conn = self.get_connection()
        try:
            if self.engine == "sqlite":
                q = query.replace("%s", "?")
                cursor = conn.cursor()
                cursor.execute(q, params or ())
                if fetchone:
                    row = cursor.fetchone()
                    return dict(row) if row else None
                if fetchall:
                    rows = cursor.fetchall()
                    return [dict(r) for r in rows]
                if commit:
                    conn.commit()
                return cursor.lastrowid
            elif self.engine == "postgres":
                is_insert = query.strip().upper().startswith("INSERT")
                actual_query = query
                if is_insert and "RETURNING" not in query.upper():
                    actual_query = query.rstrip().rstrip(";") + " RETURNING id;"

                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(actual_query, params or ())
                    if fetchone:
                        res = cursor.fetchone()
                        return dict(res) if res else None
                    if fetchall:
                        res = cursor.fetchall()
                        return [dict(r) for r in res]
                    last_id = None
                    if is_insert:
                        try:
                            row = cursor.fetchone()
                            if row and 'id' in row:
                                last_id = row['id']
                        except Exception:
                            pass
                    if commit:
                        conn.commit()
                    return last_id
            else:
                with conn.cursor() as cursor:
                    cursor.execute(query, params or ())
                    if fetchone:
                        return cursor.fetchone()
                    if fetchall:
                        return cursor.fetchall()
                    if commit:
                        conn.commit()
                    return cursor.lastrowid
        finally:
            conn.close()

    # User Auth
    def create_user(self, name, email, password_hash):
        email_clean = (email or '').strip().lower()
        q = "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)"
        return self.execute_query(q, (name, email_clean, password_hash), commit=True)

    def update_password(self, email, password_hash):
        email_clean = (email or '').strip().lower()
        q = "UPDATE users SET password_hash = %s WHERE LOWER(email) = LOWER(%s)"
        return self.execute_query(q, (password_hash, email_clean), commit=True)

    def get_user_by_email(self, email):
        email_clean = (email or '').strip().lower()
        q = "SELECT * FROM users WHERE LOWER(email) = LOWER(%s)"
        return self.execute_query(q, (email_clean,), fetchone=True)

    def get_user_by_id(self, user_id):
        q = "SELECT * FROM users WHERE id = %s"
        return self.execute_query(q, (user_id,), fetchone=True)

    # Trusted Contacts / Whitelist Logic
    def add_trusted_contact(self, contact_identifier, display_name, contact_type='PHONE', user_id=None, notes=''):
        normalized = normalize_identifier(contact_identifier)
        if not normalized:
            return None
        # Check if already trusted
        existing = self.is_trusted_contact(normalized, user_id)
        if existing:
            return existing['id']

        q = """
        INSERT INTO trusted_contacts (user_id, contact_identifier, display_name, contact_type, notes)
        VALUES (%s, %s, %s, %s, %s)
        """
        return self.execute_query(q, (user_id, normalized, display_name, contact_type, notes), commit=True)

    def is_trusted_contact(self, contact_identifier, user_id=None):
        normalized = normalize_identifier(contact_identifier)
        if not normalized:
            return None
        if user_id:
            q = "SELECT * FROM trusted_contacts WHERE contact_identifier = %s AND (user_id = %s OR user_id IS NULL) LIMIT 1"
            return self.execute_query(q, (normalized, user_id), fetchone=True)
        else:
            q = "SELECT * FROM trusted_contacts WHERE contact_identifier = %s LIMIT 1"
            return self.execute_query(q, (normalized,), fetchone=True)

    def get_trusted_contacts(self, user_id=None):
        if user_id:
            q = "SELECT * FROM trusted_contacts WHERE user_id = %s OR user_id IS NULL ORDER BY id DESC"
            return self.execute_query(q, (user_id,), fetchall=True)
        else:
            q = "SELECT * FROM trusted_contacts ORDER BY id DESC"
            return self.execute_query(q, fetchall=True)

    def delete_trusted_contact(self, contact_id, user_id=None):
        if user_id:
            q = "DELETE FROM trusted_contacts WHERE id = %s AND (user_id = %s OR user_id IS NULL)"
            return self.execute_query(q, (contact_id, user_id), commit=True)
        else:
            q = "DELETE FROM trusted_contacts WHERE id = %s"
            return self.execute_query(q, (contact_id,), commit=True)

    def mark_email_as_safe(self, email_id, contact_name="Known Contact"):
        email = self.get_email_details(email_id)
        if not email:
            return False

        # Add sender to trusted contacts
        sender = email['sender']
        contact_type = 'EMAIL' if '@' in sender else 'PHONE'
        self.add_trusted_contact(sender, contact_name, contact_type=contact_type, user_id=email.get('user_id'), notes='Whitelisted via Feedback')

        # Update email record
        q = "UPDATE emails SET classification = 'HAM', spam_probability = 1.0, is_trusted_sender = 1 WHERE id = %s"
        self.execute_query(q, (email_id,), commit=True)
        return True

    # Save Analysis
    def save_analysis(self, user_id, sender, subject, email_content, classification, spam_probability, url_analyses=None, phone_analyses=None, message_type='EMAIL', is_trusted=0):
        phone_nums_str = ", ".join([p['phone_number'] for p in (phone_analyses or [])])

        q_email = """
        INSERT INTO emails (user_id, message_type, sender, subject, email_content, classification, spam_probability, phone_numbers, is_trusted_sender)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        email_id = self.execute_query(
            q_email,
            (
                user_id,
                message_type,
                sender or ('+91-UNKNOWN' if message_type == 'SMS' else 'Unknown Sender'),
                subject or ('(SMS Message)' if message_type == 'SMS' else '(No Subject)'),
                email_content,
                classification,
                spam_probability,
                phone_nums_str,
                is_trusted
            ),
            commit=True
        )

        if url_analyses:
            q_url = """
            INSERT INTO url_analysis (email_id, url, risk_probability, risk_level, risk_type, possible_consequence, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            for u in url_analyses:
                self.execute_query(
                    q_url,
                    (email_id, u['url'], u['risk_probability'], u['risk_level'], u['risk_type'], u['possible_consequence'], u['recommendation']),
                    commit=True
                )

        if phone_analyses:
            q_phone = """
            INSERT INTO phone_analysis (email_id, phone_number, country, number_type, risk_probability, risk_level, flags)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            for p in phone_analyses:
                self.execute_query(
                    q_phone,
                    (
                        email_id,
                        p['phone_number'],
                        p.get('country', 'Unknown'),
                        p.get('number_type', 'Mobile'),
                        p.get('risk_probability', 10.0),
                        p.get('risk_level', 'LOW'),
                        json.dumps(p.get('flags', []))
                    ),
                    commit=True
                )

        return email_id

    def get_history(self, user_id=None, limit=50):
        if user_id:
            q = """
            SELECT e.*, 
                   COUNT(DISTINCT u.id) as url_count,
                   COUNT(DISTINCT p.id) as phone_count
            FROM emails e
            LEFT JOIN url_analysis u ON e.id = u.email_id
            LEFT JOIN phone_analysis p ON e.id = p.email_id
            WHERE e.user_id = %s
            GROUP BY e.id
            ORDER BY e.id DESC
            LIMIT %s
            """
            return self.execute_query(q, (user_id, limit), fetchall=True)
        else:
            q = """
            SELECT e.*, 
                   COUNT(DISTINCT u.id) as url_count,
                   COUNT(DISTINCT p.id) as phone_count
            FROM emails e
            LEFT JOIN url_analysis u ON e.id = u.email_id
            LEFT JOIN phone_analysis p ON e.id = p.email_id
            GROUP BY e.id
            ORDER BY e.id DESC
            LIMIT %s
            """
            return self.execute_query(q, (limit,), fetchall=True)

    def get_email_details(self, email_id):
        email = self.execute_query("SELECT * FROM emails WHERE id = %s", (email_id,), fetchone=True)
        if not email:
            return None
        urls = self.execute_query("SELECT * FROM url_analysis WHERE email_id = %s", (email_id,), fetchall=True)
        phones = self.execute_query("SELECT * FROM phone_analysis WHERE email_id = %s", (email_id,), fetchall=True)
        for p in phones:
            try:
                p['flags'] = json.loads(p['flags']) if p.get('flags') else []
            except:
                p['flags'] = []
        email['urls'] = urls
        email['phones'] = phones
        return email

    def get_dashboard_metrics(self, user_id=None):
        where_clause = "WHERE user_id = %s" if user_id else ""
        params = (user_id,) if user_id else ()

        total_msgs = self.execute_query(f"SELECT COUNT(*) as cnt FROM emails {where_clause}", params, fetchone=True)
        spam_msgs = self.execute_query(
            f"SELECT COUNT(*) as cnt FROM emails {where_clause} {'AND' if user_id else 'WHERE'} classification = 'SPAM'",
            params,
            fetchone=True
        )
        sms_count = self.execute_query(
            f"SELECT COUNT(*) as cnt FROM emails {where_clause} {'AND' if user_id else 'WHERE'} message_type = 'SMS'",
            params,
            fetchone=True
        )
        email_count = self.execute_query(
            f"SELECT COUNT(*) as cnt FROM emails {where_clause} {'AND' if user_id else 'WHERE'} message_type = 'EMAIL'",
            params,
            fetchone=True
        )
        total_urls = self.execute_query("SELECT COUNT(*) as cnt FROM url_analysis", fetchone=True)
        total_phones = self.execute_query("SELECT COUNT(*) as cnt FROM phone_analysis", fetchone=True)
        trusted_count = self.execute_query("SELECT COUNT(*) as cnt FROM trusted_contacts", fetchone=True)

        tot = total_msgs['cnt'] if total_msgs else 0
        spam = spam_msgs['cnt'] if spam_msgs else 0

        risk_types = self.execute_query("""
            SELECT risk_type, COUNT(*) as cnt 
            FROM url_analysis 
            GROUP BY risk_type
        """, fetchall=True)

        return {
            'total_emails': tot,
            'spam_count': spam,
            'ham_count': max(0, tot - spam),
            'sms_count': sms_count['cnt'] if sms_count else 0,
            'email_count': email_count['cnt'] if email_count else 0,
            'spam_rate': round((spam / tot * 100), 1) if tot > 0 else 0.0,
            'total_urls_scanned': total_urls['cnt'] if total_urls else 0,
            'total_phones_scanned': total_phones['cnt'] if total_phones else 0,
            'trusted_contacts_count': trusted_count['cnt'] if trusted_count else 0,
            'risk_type_distribution': {r['risk_type']: r['cnt'] for r in risk_types},
            'engine': self.engine.upper(),
            'status': self.status_msg
        }

db = Database()
