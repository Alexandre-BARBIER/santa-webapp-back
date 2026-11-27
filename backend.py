####################################################################################################
###########################################   IMPORTS   ############################################
####################################################################################################
import os
import math
import hashlib
import hmac
import re
import json
import secrets
from waitress import serve
import random

from threading import Timer

from argon2 import PasswordHasher, exceptions

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy import func, inspect as sa_inspect, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy_utils import database_exists, create_database
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

####################################################################################################
#############################################   INIT   #############################################
####################################################################################################

# Extract database configuration
username = os.environ['DB_USERNAME']
password = os.environ['DB_PASSWORD']
db_host = os.environ['DB_HOST']
db_port = os.environ['DB_PORT']
db_name = os.environ['DB_NAME']

# Extract Flask Server configuration
server_host = os.environ['SERVER_HOST']
server_port = os.environ['SERVER_PORT']
server_debug = os.environ['SERVER_DEBUG'] == "True"
if server_debug and server_host not in ('127.0.0.1', 'localhost', '::1'):
    raise SystemExit("SERVER_DEBUG=True exposes the Werkzeug debugger: SERVER_HOST must be 127.0.0.1, localhost or ::1")

# Extract Password Security configuration
PEPPER = os.environ['USER_PEPPER']
GROUP_PEPPER = os.environ['GROUP_PEPPER']

# Flask session signing key: must be stable across restarts and shared by every worker/replica
SECRET_KEY = os.environ['SECRET_KEY']
if len(SECRET_KEY) < 32:
    raise SystemExit("SECRET_KEY must be at least 32 characters long (see secret_generator.py)")

# Extract CORS configuration
cors_host = os.environ['CORS_HOST']

cors_protocol = 'https'

if server_debug:
    cors_protocol = 'http'

# Extract Account Inactivity Policy Configuration
max_inactivity_allowed = int(os.environ['MAX_INACTIVITY'])
check_interval = int(os.environ['INACTIVITY_CHECK'])

# Number of reverse proxies in front of the app (CapRover nginx = 1)
trusted_proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '1'))

# Set RATE_LIMIT_ENABLED=False to disable rate limiting (enabled by default)
rate_limit_enabled = os.environ.get('RATE_LIMIT_ENABLED', 'True').strip().lower() != 'false'

# Hours an e-mail verification link stays valid (unverified accounts older than this are purged)
EMAIL_VERIFICATION_HOURS = 24


####################################################################################################
##########################################   APP CONFIG  ###########################################
####################################################################################################

app = Flask(__name__)
if trusted_proxy_count > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxy_count)
cors_origin = cors_protocol + "://" + cors_host
CORS(app, resources={r"/api/*": {"origins": [cors_origin]}}, supports_credentials=True)

db_url = URL.create(
    "mariadb+mariadbconnector",
    username=username, password=password,
    host=db_host, port=int(db_port), database=db_name,
)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url.render_as_string(hide_password=False)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
app.config['MAIL_PORT'] = os.environ['MAIL_PORT']
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ['MAIL_USER']  # Your email
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = (os.environ['MAIL_NAME'], os.environ['MAIL_USER'])

mail = Mail(app)

if not(server_debug):
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True

db = SQLAlchemy(app)

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://", enabled=rate_limit_enabled)

def user_or_ip_key():
    if current_user.is_authenticated:
        return 'user:' + str(current_user.id)
    return get_remote_address()

def forgot_email_key():
    data = request.get_json(silent=True) or {}
    return 'forgot:' + str(data.get('email_address', '')).strip().lower()

@app.errorhandler(429)
def ratelimit_handler(e):
    message = "Too many requests, please try again later"
    return jsonify({"error": message, "status": message}), 429

@app.before_request
def enforce_origin():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and request.headers.get('Origin') != cors_origin:
        message = "Invalid origin"
        return jsonify({"error": message, "status": message}), 403

@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
    response.headers.setdefault('Cache-Control', 'no-store')
    if not server_debug:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    return response

####################################################################################################
##########################################   PEPPERING   ###########################################
####################################################################################################

def derive_hmac_key(pepper, purpose):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose).derive(pepper.encode())

USER_HMAC_KEY = derive_hmac_key(PEPPER, b"santa-zapy/user-password/hmac-sha256")
GROUP_HMAC_KEY = derive_hmac_key(GROUP_PEPPER, b"santa-zapy/group-join-code/hmac-sha256")

CURRENT_HASH_PREFIX = b"$argon2"

def hash_secret(secret, hmac_key):
    peppered = hmac.new(hmac_key, secret.encode('utf-8'), hashlib.sha256).hexdigest()
    return PasswordHasher().hash(peppered).encode('ascii')

def is_current_hash(blob):
    return isinstance(blob, bytes) and blob.startswith(CURRENT_HASH_PREFIX)

def verify_secret(blob, secret, hmac_key, legacy_pepper):
    # Returns (matches, needs_rehash). Raises on unreadable hashes; callers handle it (SEC-12).
    if is_current_hash(blob):
        peppered = hmac.new(hmac_key, secret.encode('utf-8'), hashlib.sha256).hexdigest()
        PasswordHasher().verify(blob.decode('ascii'), peppered)
        return True, False
    # Legacy format: AES-CFB(Argon2(secret + pepper)) keyed with the raw pepper. Read-only.
    iv, ciphertext = blob[:16], blob[16:]
    decryptor = Cipher(algorithms.AES(legacy_pepper.encode()), modes.CFB(iv), backend=default_backend()).decryptor()
    legacy_hash = decryptor.update(ciphertext) + decryptor.finalize()
    PasswordHasher().verify(legacy_hash, secret + legacy_pepper)
    return True, True

####################################################################################################
##############################################   DB   ##############################################
####################################################################################################

class User(UserMixin, db.Model):
    
    # class for the user table of the database
    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    login = db.Column(db.String(100), unique=True)
    hashed_and_peppered_password = db.Column(db.LargeBinary)
    birthdate = db.Column(db.Date())
    email_address = db.Column(db.String(100), unique=True)
    creation_date = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self,first_name, surname, login, password, birthdate, email_address, email_verified=False):
        self.first_name = first_name
        self.surname = surname
        self.login = login
        self.hashed_and_peppered_password = hash_secret(password, USER_HMAC_KEY)
        self.birthdate = birthdate
        self.email_address = email_address
        self.creation_date = datetime.now()
        self.last_login = datetime.now()
        self.email_verified = email_verified

    def update(self,first_name, surname, login, birthdate, email_address):
        self.first_name = first_name
        self.surname = surname
        self.login = login
        self.birthdate = birthdate
        self.email_address = email_address


    def check_password(self,password_to_check):
        if not isinstance(password_to_check, str):
            return False
        try:
            matches, needs_rehash = verify_secret(self.hashed_and_peppered_password, password_to_check, USER_HMAC_KEY, PEPPER)
        except exceptions.VerifyMismatchError:
            return False
        except (exceptions.VerificationError, exceptions.InvalidHashError, ValueError, TypeError):
            app.logger.exception(f"Unreadable password hash for user {self.id}")
            return False
        if needs_rehash:
            self.update_password(password_to_check)
        return matches

    def update_password(self, new_password):
        self.hashed_and_peppered_password = hash_secret(new_password, USER_HMAC_KEY)
    
    def get_session_token(self):
        return hashlib.sha256(self.hashed_and_peppered_password).hexdigest()[:32]

    def get_id(self):
        return f"{self.id}:{self.get_session_token()}"

    def update_last_login(self):
        self.last_login = datetime.now()

class Gift(db.Model):

    # class for a group containing gift listing and offering graph
    giftID = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    description = db.Column(db.String(200))
    price = db.Column(db.Float)
    receiverID = db.Column(db.Integer)
    gifterID = db.Column(db.Integer)
    image_url = db.Column(db.String(200))

    def __init__(self, name, description, price, receiverID, image_url):
        self.name = name
        self.description = description
        self.price = price
        self.receiverID = receiverID
        self.gifterID = 0
        self.image_url = image_url

    def set_gifter(self, gifterID):
        if (self.gifterID == 0) and (self.receiverID != gifterID):
            self.gifterID = gifterID
            return 0
        else:
            return 1
    
    def unset_gifter(self, gifterID):
        #Check that person trying to unselect gift was previously the one who had selected iter
        if self.gifterID == gifterID:
            self.gifterID = 0
            return 0
        else:
            return 1     

class GiftGroup(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    visibility = db.Column(db.String(100))
    join_code = db.Column(db.LargeBinary)
    hint = db.Column(db.String(100))
    creatorID = db.Column(db.String(100))
    secret_santa_active = db.Column(db.Boolean)
    secret_santa_date = db.Column(db.Date)

    def __init__(self, name, visibility, join_code, creatorID):
        self.name = name
        self.visibility = visibility
        self.join_code = hash_secret(join_code, GROUP_HMAC_KEY)
        if len(join_code) == 1:
            self.hint = join_code
        else:
            self.hint = join_code[:1] + '*' * (len(join_code) - 2) + join_code[-1:]
        self.creatorID = creatorID
        self.secret_santa_active = False
        self.secret_santa_date = datetime.now()

    def check_join_code(self,code_to_check):
        if not isinstance(code_to_check, str):
            return False
        try:
            matches, needs_rehash = verify_secret(self.join_code, code_to_check, GROUP_HMAC_KEY, GROUP_PEPPER)
        except exceptions.VerifyMismatchError:
            return False
        except (exceptions.VerificationError, exceptions.InvalidHashError, ValueError, TypeError):
            app.logger.exception(f"Unreadable join code hash for group {self.id}")
            return False
        if needs_rehash:
            self.join_code = hash_secret(code_to_check, GROUP_HMAC_KEY)
        return matches
    
    def change_join_code(self,new_join_code):
        self.join_code = hash_secret(new_join_code, GROUP_HMAC_KEY)
        if len(new_join_code) == 1:
            self.hint = new_join_code
        else:
            self.hint = new_join_code[:1] + '*' * (len(new_join_code) - 2) + new_join_code[-1:]


class GiftGroupMember(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    groupID = db.Column(db.Integer)
    memberID = db.Column(db.Integer)

    def __init__(self, groupID, memberID):
       self.groupID = groupID
       self.memberID = memberID

class SecretSantaPair(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    receiverID = db.Column(db.Integer)
    gifterID = db.Column(db.Integer)
    groupID = db.Column(db.Integer)

    def __init__(self, receiverID, gifterID, groupID):
       self.receiverID = receiverID
       self.gifterID = gifterID
       self.groupID = groupID

class SecretSantaExclusion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupID = db.Column(db.Integer)
    userID = db.Column(db.Integer)  # The user who cannot be paired with excludedUserID
    excludedUserID = db.Column(db.Integer)  # The user who should not receive a gift from userID

    def __init__(self, groupID, userID, excludedUserID):
        self.groupID = groupID
        self.userID = userID
        self.excludedUserID = excludedUserID

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, user_id, token, expiration_hours=1):
        self.user_id = user_id
        self.token = token
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(hours=expiration_hours)
        self.used = False

    def is_valid(self):
        return not self.used and datetime.now() < self.expires_at


class EmailVerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, user_id, email, token, expiration_hours=EMAIL_VERIFICATION_HOURS):
        self.user_id = user_id
        self.email = email
        self.token = token
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(hours=expiration_hours)
        self.used = False

    def is_valid(self):
        return not self.used and datetime.now() < self.expires_at


class GroupInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupID = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, groupID, email, token, expiration_days=7):
        self.groupID = groupID
        self.email = email
        self.token = token
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(days=expiration_days)
        self.used = False

    def is_valid(self):
        return not self.used and datetime.now() < self.expires_at

####################################################################################################
###########################################   FONCTIONS   ##########################################
####################################################################################################

def in_same_group(user1, user2):
    user1_groups = db.session.query(GiftGroupMember).filter(GiftGroupMember.memberID == user1).all()
    user2_groups = db.session.query(GiftGroupMember).filter(GiftGroupMember.memberID == user2).all()

    groups_1 = []
    for entry in user1_groups:
        groups_1.append(entry.groupID)
    for entry in user2_groups:
        if entry.groupID in groups_1:
            return True
    return False

def user_in_group(userid, groupid):
    membership = db.session.query(GiftGroupMember).filter(GiftGroupMember.memberID == userid, GiftGroupMember.groupID == groupid).all()

    return (membership != [])

def invalidate_reset_tokens(user_id):
    db.session.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user_id, PasswordResetToken.used == False
    ).update({PasswordResetToken.used: True})

def string_to_date(datestring):
    try:
        birthdate = datetime.strptime(datestring, '%d/%m/%Y')
        return birthdate
    except ValueError:
        return "Incorrect date format"   

def date_to_string(date):
    return date.strftime("%d/%m/%Y")

def sanitize_email(email):
    email = email.strip()
    email = email.lower()
    
    # Use a regular expression to validate the email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return None  # Return None if the email is invalid
    return email

def hash_token(token):
    return hashlib.sha256(str(token).encode()).hexdigest()

LOGIN_MAX_LENGTH = 100

def is_valid_login(login):
    return isinstance(login, str) and login.strip() != '' and len(login) <= LOGIN_MAX_LENGTH and '@' not in login

PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128

def is_valid_password(password):
    return isinstance(password, str) and PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH

def duplicate_user_message(login, user_id=None):
    query = db.session.query(User).filter(User.login == login)
    if user_id is not None:
        query = query.filter(User.id != user_id)
    if query.first() is not None:
        return "Login already used"
    return "Email already used"

GIFT_NAME_MAX_LENGTH = 100
GIFT_DESCRIPTION_MAX_LENGTH = 200
GIFT_PRICE_MAX = 1000000

def send_group_invitation_email(recipient, group_name, inviter_login, invite_link):
    group_name_html = escape(group_name)
    inviter_login_html = escape(inviter_login)
    invite_link_html = escape(invite_link)
    subject = f"Invitation to join {group_name} on Santa Zapy"
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <table style="width: 100%; max-width: 600px; margin: 0 auto; border-collapse: collapse; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
            <thead>
                <tr style="background-color: #f4f4f4; border-bottom: 1px solid #ddd;">
                    <th style="padding: 15px; text-align: left;">
                        <h2 style="margin: 0; color: #333;">You're invited!</h2>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="padding: 20px;">
                        <p>Hello,</p>
                        <p>{inviter_login_html} invites you to join the group <b>{group_name_html}</b> on Santa Zapy to organise your Christmas gifts. Create your account with the button below and you will be added to the group automatically.</p>

                        <div style="text-align: center; margin: 20px 0;">
                            <a href="{invite_link_html}" style="display: inline-block; padding: 15px 30px; background-color: #dc3545; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">Create my account</a>
                        </div>
                        <p style="font-size: 14px; color: #666;">If the button doesn't work, use this link instead:</p>
                        <p style="word-break: break-all;"><a href="{invite_link_html}" style="color: #007BFF;">{invite_link_html}</a></p>
                        <p style="font-size: 12px; color: #888; margin-top: 20px;">This invitation will expire in 7 days.</p>

                        <p>Thank you for choosing our service. If you have any questions or need further assistance, don't hesitate to reach out.</p>
                        <p>Best regards,</p>
                        <p style="font-weight: bold;">Santa Zapy<br></p>
                    </td>
                </tr>
                <tr style="background-color: #f4f4f4;">
                    <td style="text-align: center; padding: 10px;">
                        <p style="margin: 0; font-size: 12px; color: #888;">© 2025 Santa Zapy. All rights reserved.</p>
                    </td>
                </tr>
            </tbody>
        </table>
    </body>
    </html>
    """
    mail.send(Message(subject, recipients=[recipient], html=body))

def send_verification_email(recipient, first_name, verify_link):
    first_name_html = escape(first_name)
    verify_link_html = escape(verify_link)
    subject = "Confirm your email address on Santa Zapy"
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <table style="width: 100%; max-width: 600px; margin: 0 auto; border-collapse: collapse; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
            <thead>
                <tr style="background-color: #f4f4f4; border-bottom: 1px solid #ddd;">
                    <th style="padding: 15px; text-align: left;">
                        <h2 style="margin: 0; color: #333;">Confirm your email address</h2>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="padding: 20px;">
                        <p>Hello {first_name_html},</p>
                        <p>Please confirm your email address by clicking the button below.</p>

                        <div style="text-align: center; margin: 20px 0;">
                            <a href="{verify_link_html}" style="display: inline-block; padding: 15px 30px; background-color: #dc3545; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">Confirm my email</a>
                        </div>
                        <p style="font-size: 14px; color: #666;">If the button doesn't work, use this link instead:</p>
                        <p style="word-break: break-all;"><a href="{verify_link_html}" style="color: #007BFF;">{verify_link_html}</a></p>
                        <p style="font-size: 12px; color: #888; margin-top: 20px;">This link will expire in 24 hours.</p>

                        <p>Best regards,</p>
                        <p style="font-weight: bold;">Santa Zapy<br></p>
                    </td>
                </tr>
                <tr style="background-color: #f4f4f4;">
                    <td style="text-align: center; padding: 10px;">
                        <p style="margin: 0; font-size: 12px; color: #888;">© 2025 Santa Zapy. All rights reserved.</p>
                    </td>
                </tr>
            </tbody>
        </table>
    </body>
    </html>
    """
    mail.send(Message(subject, recipients=[recipient], html=body))

def create_email_verification(user, email):
    raw_token = secrets.token_urlsafe(32)
    db.session.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id, EmailVerificationToken.used == False
    ).update({EmailVerificationToken.used: True})
    db.session.add(EmailVerificationToken(user.id, email, hash_token(raw_token)))
    return f"{cors_protocol}://{cors_host}/verify-email/{raw_token}"

def delete_stale_unverified_users(login, email):
    threshold = datetime.now() - timedelta(hours=EMAIL_VERIFICATION_HOURS)
    conditions = [User.login == login]
    if email:
        conditions.append(User.email_address == email)
    stale_users = db.session.query(User).filter(
        User.email_verified == False, User.creation_date <= threshold,
        db.or_(*conditions),
    ).all()
    for stale_user in stale_users:
        delete_user_account(stale_user)
    db.session.commit()

def delete_user_account(user):
    # Removes the user and everything that references it. The caller commits.
    admin_groups = db.session.query(GiftGroup).filter(GiftGroup.creatorID == str(user.id)).all()

    for group in admin_groups:
        members = db.session.query(GiftGroupMember).filter(GiftGroupMember.groupID == group.id).all()
        pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == group.id).all()
        invitations = db.session.query(GroupInvitation).filter(GroupInvitation.groupID == group.id).all()
        exclusions = db.session.query(SecretSantaExclusion).filter(SecretSantaExclusion.groupID == group.id).all()
        db.session.delete(group)

        for member in members:
            db.session.delete(member)
        for pair in pairs:
            db.session.delete(pair)
        for invitation in invitations:
            db.session.delete(invitation)
        for exclusion in exclusions:
            db.session.delete(exclusion)

    memberships = db.session.query(GiftGroupMember).filter(GiftGroupMember.memberID == user.id).all()
    for membership in memberships:
        db.session.delete(membership)

    gifter_pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.gifterID == user.id).all()
    for pair in gifter_pairs:
        pair.gifterID = -1
    receiver_pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.receiverID == user.id).all()
    for pair in receiver_pairs:
        pair.receiverID = -1

    db.session.query(Gift).filter(Gift.receiverID == user.id).delete(synchronize_session=False)
    db.session.query(Gift).filter(Gift.gifterID == user.id).update({Gift.gifterID: 0}, synchronize_session=False)

    db.session.query(SecretSantaExclusion).filter(
        db.or_(SecretSantaExclusion.userID == user.id, SecretSantaExclusion.excludedUserID == user.id)
    ).delete(synchronize_session=False)
    db.session.query(GroupInvitation).filter(GroupInvitation.email == user.email_address).delete(synchronize_session=False)
    db.session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete(synchronize_session=False)
    db.session.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).delete(synchronize_session=False)

    db.session.delete(user)

def apply_schema_migrations():
    inspector = sa_inspect(db.engine)
    user_columns = {column['name'] for column in inspector.get_columns('user')}
    if 'email_verified' not in user_columns:
        with db.engine.begin() as connection:
            connection.execute(text("ALTER TABLE `user` ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 1"))
    unique_columns = {tuple(index['column_names']) for index in inspector.get_indexes('user') if index.get('unique')}
    unique_columns |= {tuple(constraint['column_names']) for constraint in inspector.get_unique_constraints('user')}
    for column in ('login', 'email_address'):
        if (column,) in unique_columns:
            continue
        try:
            with db.engine.begin() as connection:
                connection.execute(text(f"ALTER TABLE `user` ADD CONSTRAINT uq_user_{column} UNIQUE ({column})"))
        except SQLAlchemyError:
            app.logger.exception(f"Could not add a unique constraint on user.{column}: remove the duplicate values, then restart")

def log_legacy_hash_count():
    legacy_users = sum(1 for (blob,) in db.session.query(User.hashed_and_peppered_password) if not is_current_hash(blob))
    legacy_groups = sum(1 for (blob,) in db.session.query(GiftGroup.join_code) if not is_current_hash(blob))
    app.logger.warning(f"Legacy AES-CFB hashes remaining: {legacy_users} user password(s), {legacy_groups} group join code(s)")

def generate_secret_pairs(users, group):
    
    # Get all exclusions for this group
    exclusions = db.session.query(SecretSantaExclusion).filter(SecretSantaExclusion.groupID == group).all()

    # Create a dictionary of excluded receivers for each user
    excluded_receivers = {}
    for user in users:
        excluded_receivers[user] = [e.excludedUserID for e in exclusions if e.userID == user]

    # Create a copy of users for receivers
    available_receivers = users.copy()
    gifters = users.copy()
    pairs = []

    # Try to find a valid assignment using backtracking
    if find_valid_assignment(gifters, available_receivers, excluded_receivers, pairs):
        
        # Save the pairs to the database
        for pair in pairs:
            gifter, receiver = pair
            santa_pair = SecretSantaPair(receiver, gifter, group)
            db.session.add(santa_pair)
        db.session.commit()
        return 'OK'
    else:
        return 'Cannot create valid pairings with current exclusions'

def find_valid_assignment(gifters, available_receivers, excluded_receivers, pairs):
    
    # Base case: all gifters have been assigned
    if not gifters:
        return True
    
    random.shuffle(gifters)
    random.shuffle(available_receivers)

    current_gifter = gifters[0]
    remaining_gifters = gifters[1:]
    
    # Try each available receiver
    for i, receiver in enumerate(available_receivers):

        # Skip if the receiver is the gifter or in the exclusion list
        if receiver == current_gifter or receiver in excluded_receivers.get(current_gifter, []):
            continue
        
        # Try this receiver
        new_available_receivers = available_receivers.copy()
        new_available_receivers.pop(i)
        pairs.append((current_gifter, receiver))
        
        # Recursively try to assign the rest
        if find_valid_assignment(remaining_gifters, new_available_receivers, excluded_receivers, pairs):
            return True
        
        # If we get here, this receiver didn't work out, backtrack
        pairs.pop()
    
    # If we get here, no valid receiver was found
    return False
    

####################################################################################################
########################################  INACTIVE USERS   #########################################
####################################################################################################

def delete_inactive_users():
    now = datetime.now()
    inactive_users = db.session.query(User).filter(db.or_(
        User.last_login <= now - timedelta(days=max_inactivity_allowed),
        db.and_(User.email_verified == False, User.creation_date <= now - timedelta(hours=EMAIL_VERIFICATION_HOURS)),
    )).all()
    for user in inactive_users:
        delete_user_account(user)
    db.session.commit()

def check_inactive_users_periodically():
    try:
        with app.app_context():
            delete_inactive_users()
    except Exception:
        app.logger.exception("Inactive users purge failed")
    # Schedule the next execution of this function
    timer = Timer(check_interval, check_inactive_users_periodically)
    timer.daemon = True
    timer.start()


####################################################################################################
#############################################   ROUTE   ############################################
####################################################################################################

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return "Logged out"

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute;50 per hour")
def login():
    login = request.get_json()['login']
    password = request.get_json()['password']
    if not isinstance(login, str) or not isinstance(password, str) or len(password) > PASSWORD_MAX_LENGTH:
        return "Login ou mot de passe incorrect"
    
    remember_me_string = request.get_json()['remember_me']
    
    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False


    if '@' in login:
        user = db.session.query(User).filter(User.email_address == login.strip().lower()).first()
    else:
        user = db.session.query(User).filter(User.login == login).first()

    if not user or not user.check_password(password):
        return "Login ou mot de passe incorrect"
    else:
        if not user.email_verified:
            return "Email not verified"
        user.update_last_login()
        db.session.commit()
        login_user(user, remember=remember_me)
        return "Vous êtes connecté!"
    

@app.route('/api/signup', methods = ['POST'])
@limiter.limit("5 per hour")
def signup():
    signup_request = request.get_json()
    if not is_valid_login(signup_request['login']):
        return "Invalid login"
    if not is_valid_password(signup_request['password']):
        return "Invalid password"

    clean_email = sanitize_email(signup_request['email_address'])

    invite_token = signup_request.get('invite_token')
    invitation = None
    if invite_token:
        invitation = db.session.query(GroupInvitation).filter(GroupInvitation.token == hash_token(invite_token)).first()
        if invitation is None or not invitation.is_valid():
            return "Invalid or expired invitation"
        if clean_email != invitation.email:
            return "Email does not match the invitation"

    delete_stale_unverified_users(signup_request['login'], clean_email)

    dbentry_user = db.session.query(User).filter(User.login == signup_request['login']).first()
    dbentry_email = db.session.query(User).filter(User.email_address == clean_email).first()

    remember_me_string = request.get_json()['remember_me']

    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False

    if dbentry_user != None:
        return "Login already used"
    if dbentry_email != None:
        return "Email already used"

    birthdate = string_to_date(signup_request['birthdate'])
    if birthdate == "Incorrect date format":
        return "Incorrect date format"
    if not clean_email:
        return 'Incorrect email format'

    user = User(signup_request['first_name'], signup_request['surname'], signup_request['login'], signup_request['password'], birthdate, clean_email, email_verified=invitation is not None)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return duplicate_user_message(signup_request['login'])

    if invitation is not None:
        pending_invitations = db.session.query(GroupInvitation).filter(
            GroupInvitation.email == clean_email
        ).all()
        for pending in pending_invitations:
            if not pending.is_valid():
                continue
            pending.used = True
            invited_group = db.session.query(GiftGroup).filter(GiftGroup.id == pending.groupID).first()
            if invited_group is not None and not invited_group.secret_santa_active and not user_in_group(user.id, pending.groupID):
                db.session.add(GiftGroupMember(pending.groupID, user.id))
        db.session.commit()
        login_user(user, remember=remember_me)
        return "Inscription réussie"

    verify_link = create_email_verification(user, clean_email)
    db.session.commit()
    try:
        send_verification_email(clean_email, user.first_name, verify_link)
    except Exception:
        app.logger.exception("Failed to send verification email")
        delete_user_account(user)
        db.session.commit()
        return "Failed to send the verification email"
    return "Verification email sent"

@app.route('/api/forgotpassword', methods=['POST'])
@limiter.limit("5 per hour")
@limiter.limit("3 per hour", key_func=forgot_email_key)
def forgotpassword():
    email = str((request.get_json(silent=True) or {}).get('email_address') or '').strip().lower()
    generic = jsonify({"message": "If an account exists with this email, a password reset link has been sent"}), 200

    user = db.session.query(User).filter(User.email_address == email).first()

    if not user:
        return generic

    # Generate secure reset token (only its hash is stored)
    reset_token = secrets.token_urlsafe(64)

    password_reset = PasswordResetToken(user_id=user.id, token=hash_token(reset_token), expiration_hours=1)
    db.session.add(password_reset)
    db.session.commit()

    # Build reset link
    reset_link = f"{cors_protocol}://{cors_host}/reset-password/{reset_token}"

    try:
        recipient = user.email_address
        subject = 'Reset Password Santa'
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <table style="width: 100%; max-width: 600px; margin: 0 auto; border-collapse: collapse; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background-color: #f4f4f4; border-bottom: 1px solid #ddd;">
                        <th style="padding: 15px; text-align: left;">
                            <h2 style="margin: 0; color: #333;">Password Reset Request</h2>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="padding: 20px;">
                            <p>Dear {escape(user.first_name)} {escape(user.surname)},</p>
                            <p>We have successfully processed your request to reset your password. Below is a link for you to reset your password:</p>

                            <div style="text-align: center; margin: 20px 0;">
                                <a href="{escape(reset_link)}" style="display: inline-block; padding: 15px 30px; background-color: #dc3545; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">Reset My Password</a>
                            </div>
                            <p style="font-size: 14px; color: #666;">If the button doesn't work, use this link instead:</p>
                            <p style="word-break: break-all;"><a href="{escape(reset_link)}" style="color: #007BFF;">{escape(reset_link)}</a></p>
                            <p style="font-size: 12px; color: #888; margin-top: 20px;">This link will expire in 1 hour.</p>
                            
                            <p style="color: #888;">If you didn’t request a password reset or believe this message was sent in error, please contact me immediately at <a href="mailto:{escape(os.environ['MAIL_USER'])}" style="color: #007BFF;">{escape(os.environ['MAIL_USER'])}</a></p>
                            <p>Thank you for choosing our service. If you have any questions or need further assistance, don't hesitate to reach out.</p>
                            <p>Best regards,</p>
                            <p style="font-weight: bold;">Santa Zapy<br></p>
                        </td>
                    </tr>
                    <tr style="background-color: #f4f4f4;">
                        <td style="text-align: center; padding: 10px;">
                            <p style="margin: 0; font-size: 12px; color: #888;">© 2025 Santa Zapy. All rights reserved.</p>
                        </td>
                    </tr>
                </tbody>
            </table>
        </body>
        </html>
        """

        # Create and send the email
        msg = Message(subject, recipients=[recipient], html=body)
        mail.send(msg)
    except Exception:
        app.logger.exception("Failed to send password reset email")

    return generic

@app.route('/api/validate-reset-token', methods=['GET'])
def validate_reset_token():
    token = request.args.get('token')
    
    if not token:
        return jsonify({"valid": False, "error": "Token is required"}), 400
    
    reset_token = db.session.query(PasswordResetToken).filter(PasswordResetToken.token == hash_token(token)).first()
    
    if not reset_token:
        return jsonify({"valid": False, "error": "Invalid token"}), 404
    
    if not reset_token.is_valid():
        return jsonify({"valid": False, "error": "Token has expired or already been used"}), 400
    
    user = db.session.query(User).filter(User.id == reset_token.user_id).first()
    
    return jsonify({
        "valid": True,
        "first_name": user.first_name,
        "user_id": user.id
    }), 200

@app.route('/api/invitation/validate', methods=['GET'])
def validate_invitation():
    token = request.args.get('token')
    invalid = jsonify({"valid": False, "error": "Invalid or expired invitation"})

    if not token:
        return invalid

    invitation = db.session.query(GroupInvitation).filter(GroupInvitation.token == hash_token(token)).first()
    if invitation is None or not invitation.is_valid():
        return invalid

    group = db.session.query(GiftGroup).filter(GiftGroup.id == invitation.groupID).first()
    if group is None:
        return invalid

    return jsonify({"valid": True, "email": invitation.email, "group_name": group.name})

@app.route('/api/verify-email', methods=['POST'])
@limiter.limit("10 per hour")
def verify_email():
    token = (request.get_json(silent=True) or {}).get('token')
    invalid = jsonify({'status': 'Invalid or expired link'}), 400
    if not isinstance(token, str) or token == '':
        return invalid
    entry = db.session.query(EmailVerificationToken).filter(EmailVerificationToken.token == hash_token(token)).first()
    if entry is None or not entry.is_valid():
        return invalid
    user = db.session.get(User, entry.user_id)
    if user is None:
        return invalid
    if db.session.query(User).filter(User.email_address == entry.email, User.id != user.id).first() is not None:
        entry.used = True
        db.session.commit()
        return jsonify({'status': 'Email already used'}), 409
    user.email_address = entry.email
    user.email_verified = True
    db.session.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id, EmailVerificationToken.used == False
    ).update({EmailVerificationToken.used: True})
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'status': 'Email already used'}), 409
    return jsonify({'status': 'Email verified'})

@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    reset_request = request.get_json()
    token = reset_request.get('token')
    new_password = reset_request.get('new_password')
    
    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400

    if not is_valid_password(new_password):
        return jsonify({"error": f"Password must be between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters"}), 400
    
    reset_token = db.session.query(PasswordResetToken).filter(PasswordResetToken.token == hash_token(token)).first()
    
    if not reset_token:
        return jsonify({"error": "Invalid token"}), 404
    
    if not reset_token.is_valid():
        return jsonify({"error": "Token has expired or already been used"}), 400
    
    user = db.session.query(User).filter(User.id == reset_token.user_id).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Update user password
    user.update_password(new_password)
    user.email_verified = True
    
    # Revoke every outstanding reset token (including the current one)
    invalidate_reset_tokens(user.id)
    
    db.session.commit()
    
    return jsonify({"message": "Password successfully reset"}), 200

@app.route('/api/changepassword', methods = ['PUT'])
@limiter.limit("10 per hour", key_func=user_or_ip_key)
@login_required
def changepassword():
    user_id = current_user.id
    user = db.session.query(User).filter(User.id==user_id).first()
    change_password_request = request.get_json()
    
    if not is_valid_password(change_password_request['new_password']):
        return "Invalid password"
    elif user.check_password(change_password_request['new_password']):
        return "No change made"
    elif not(user.check_password(change_password_request['old_password'])):
        return "No change made, Wrong Password"
    else :
        user.update_password(change_password_request['new_password'])
        invalidate_reset_tokens(user.id)
        db.session.commit()
        login_user(user, remember='remember_token' in request.cookies)
        return "Update Password"

@app.route('/api/user/delete', methods = ['DELETE'])
@limiter.limit("10 per hour", key_func=user_or_ip_key)
@login_required
def delete_user():
    user_id = current_user.id
    user = db.session.query(User).filter(User.id==user_id).first()
    delete_request = request.get_json()
    if not(user.check_password(delete_request['password'])):
        return "Wrong password"

    delete_user_account(user)
    db.session.commit()

    logout_user()

    return "User deleted"

@app.route('/api/changeprofile', methods = ['PUT'])
@limiter.limit("10 per hour", key_func=user_or_ip_key)
@login_required
def changeprofile():
    req = request.get_json()
    user = current_user
    if not is_valid_login(req['login']):
        return "Invalid login"
    if db.session.query(User).filter(User.login == req['login'], User.id != user.id).first() is not None:
        return "Login already used"

    if req['birthdate'] == "":
        birthdate = user.birthdate
    else:
        birthdate = string_to_date(req['birthdate'])
    if req['email_address'] == "":
        new_email = user.email_address
    else:
        new_email = sanitize_email(req['email_address'])
    if birthdate == "Incorrect date format" or not new_email:
        return "Incorrect format"

    email_changed = new_email != user.email_address
    if email_changed and db.session.query(User).filter(User.email_address == new_email, User.id != user.id).first() is not None:
        return "Email already used"

    # The current email is kept until the new one is confirmed
    user.update(req['first_name'], req['surname'], req['login'], birthdate, user.email_address)

    if not email_changed:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return duplicate_user_message(req['login'], user.id)
        return "Updated Profile"

    verify_link = create_email_verification(user, new_email)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return duplicate_user_message(req['login'], user.id)
    try:
        send_verification_email(new_email, user.first_name, verify_link)
    except Exception:
        app.logger.exception("Failed to send verification email")
        return "Failed to send the verification email"
    return "Verification email sent"

@app.route('/api/profile/<int:userid>', methods = ['GET'])
@login_required
def profile(userid):
    dbentry = db.session.query(User).filter(User.id == userid).first()
    if dbentry is None:
        abort(404)
    is_self = dbentry.id == current_user.id
    if not is_self and not in_same_group(userid, current_user.id):
        abort(404)
    record = {
        "first_name": dbentry.first_name,
        "surname": dbentry.surname,
        "login": dbentry.login,
        "birthdate": date_to_string(dbentry.birthdate),
        "email_address": dbentry.email_address if is_self else "",
    }
    return jsonify(record)

@app.route('/api/myprofile', methods = ['GET'])
@login_required
def myprofile():
    record_json = jsonify({"user_id":current_user.id})
    return record_json


@app.route('/api/mygifts', methods=['GET'])
@login_required
def mygifts():
    user_id = current_user.id
    gifts = db.session.query(Gift).filter(Gift.receiverID == user_id).all()
    gifts_list = [{
        "giftID": gift.giftID,
        "name": gift.name,
        "description": gift.description,
        "price": gift.price,
        "receiverID": gift.receiverID,
        "image_url": gift.image_url
    } for gift in gifts]
    return jsonify(gifts_list)

@app.route('/api/gift/group/<int:group_id>', methods=['GET'])
@login_required
def group_gifts(group_id):
    user_id = current_user.id

    
    if user_in_group(user_id, group_id):
        gift_members = db.session.query(GiftGroupMember).filter_by(groupID=group_id).all()
        users = set()
        for gift_member in gift_members:
            users.add(gift_member.memberID)

        all_gifts = []

        for user in users:
            if user != user_id:
                gifts = db.session.query(Gift).filter(Gift.receiverID == user).all()
                for gift in gifts:
                    receiver = db.session.query(User).filter(User.id == gift.receiverID).first()
                    all_gifts.append({
                        "giftID": gift.giftID,
                        "name": gift.name,
                        "description": gift.description,
                        "price": gift.price,
                        "receiverID": gift.receiverID,
                        "receiverLogin": receiver.login,
                        "gifterID": gift.gifterID,
                        "image_url": gift.image_url
                    })

        return jsonify(all_gifts)
    else:
        abort(401)


@app.route('/api/gift/add', methods = ['POST'])
@login_required
def add_gift():
    userid = current_user.id
    add_request = request.get_json()
    name = add_request.get('name')
    description = add_request.get('description', '')
    if not isinstance(name, str) or name.strip() == '' or len(name) > GIFT_NAME_MAX_LENGTH:
        return 'Invalid name'
    if not isinstance(description, str) or len(description) > GIFT_DESCRIPTION_MAX_LENGTH:
        return 'Invalid description'
    try:
        price = float(add_request.get('price'))
    except (TypeError, ValueError):
        return 'Incorrect Price'
    if not math.isfinite(price) or price < 0 or price > GIFT_PRICE_MAX:
        return 'Incorrect Price'
    gift = Gift(name, description, price, userid, '')
    db.session.add(gift)
    db.session.commit()
    return "Gift Added"

@app.route('/api/gift/select', methods = ['POST'])
@login_required
def select_gift():
    userid = current_user.id
    giftid = request.get_json()['gift_id']
    
    try:
        giftid = int(giftid)
    except:
        return "Invalid gift ID"

    dbentry = db.session.query(Gift).filter(Gift.giftID == giftid).first()
    if dbentry != None:
        if in_same_group(dbentry.receiverID, userid):
            dbentry.set_gifter(userid)
            db.session.commit()
            return "Gift Selected"
        else:
            abort(401)
    else:
        abort(404)

@app.route('/api/gift/unselect', methods = ['POST'])
@login_required
def unselect_gift():
    userid = current_user.id
    giftid = request.get_json()['gift_id']
    
    try:
        giftid = int(giftid)
    except:
        return "Invalid gift ID"

    dbentry = db.session.query(Gift).filter(Gift.giftID == giftid).first()
    
    if dbentry != None:
        dbentry.unset_gifter(userid)
        db.session.commit()
        return "Gift Unselected"
    else:
        abort(404)

@app.route('/api/gift/delete', methods = ['DELETE'])
@login_required
def delete_gift():
    userid = current_user.id
    giftid = request.get_json()['gift_id']
    
    try:
        giftid = int(giftid)
    except:
        return "Invalid gift ID"


    dbentry = db.session.query(Gift).filter(Gift.giftID == giftid).first()

    if dbentry == None:
        abort(404)
    if dbentry.receiverID == userid:
        db.session.delete(dbentry)
        db.session.commit()
        return "The gift has been removed."
    return "Not removed"




@app.route('/api/mygroups', methods=['GET'])
@login_required
def my_groups():
    user_id = current_user.id
    
    # Joining GroupsMembers and Groups tables on groupID
    user_groups = db.session.query(GiftGroupMember, GiftGroup).join(GiftGroup, GiftGroupMember.groupID == GiftGroup.id).filter(GiftGroupMember.memberID == user_id).all()
    groups = []
    
    for membership, group in user_groups:
        if group.secret_santa_active:
            secret_santa = "Yes"
        else:
            secret_santa = ""
        groups.append({"id": group.id, "name": group.name, "secret_santa": secret_santa})
    groups = sorted(groups, key=lambda x: x['id'])
    return jsonify(groups)

@app.route('/api/group/all', methods=['GET'])
@login_required
def show_groups():
    db_groups = db.session.query(GiftGroup).all()
    groups = []
    for group in db_groups:
        group_data = {
            'id': group.id, 
            'name': group.name,
            'visibility': group.visibility
        }
        groups.append(group_data)
    return jsonify(groups)

@app.route('/api/group/create', methods=['POST'])
@login_required
def create_group():
    user_id = current_user.id
    create_request = request.get_json()
    
    create_request = request.get_json()

    if not(create_request['visibility'] == 'protected' or create_request['visibility'] == 'public'):
        return 'Invalid Visibility'

    group = GiftGroup(create_request['groupName'], create_request['visibility'], create_request['join_code'], user_id)
    db.session.add(group)
    db.session.commit()
    return "Group created"


@app.route('/api/group/admin', methods=['GET'])
@login_required
def group_admin():
    user_id = current_user.id
    groups_administred = db.session.query(GiftGroup).filter(GiftGroup.creatorID == user_id).all()
    
    group_list = []
    for group in groups_administred:
        if group.secret_santa_active:
            secret_santa = "Yes"
        else:
            secret_santa = "" 
        group_list.append({
            "id" : group.id,
            "name" : group.name,
            "visibility" : group.visibility,
            "join_code" : group.hint,
            "secret_santa": secret_santa
        })

    return jsonify(group_list)

@app.route('/api/group/info/<int:group_id>', methods=['GET'])
@login_required
def group_info(group_id):
    user_id = current_user.id
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group == None:
        return jsonify({'status':'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status':'You are not an admin of the group'})

    group_json = {
        "id" : group.id,
        "name" : group.name,
        "visibility" : group.visibility,
        "join_code" : group.hint
    }

    gift_group_members = db.session.query(GiftGroupMember).filter_by(groupID=group_id).all()
    userids = set()
    for gift_group_member in gift_group_members:
        userids.add(gift_group_member.memberID)
    group_users = []
    for userid in userids:
        user = db.session.query(User).filter(User.id==userid).first()
        group_users.append({"id": user.id, "login": user.login})
    group_json['members'] = group_users
    group_json['status'] = 'OK'
    return jsonify(group_json)

@app.route('/api/group/update', methods=['POST'])
@login_required
def update_group():
    user_id = current_user.id
    update_request = request.get_json()
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == update_request['groupID']).first()

    if group == None:
        return "Group does not exist"

    if str(group.creatorID) != str(user_id):
        return "You are not an admin of the group"


    if not(update_request['visibility'] == 'protected' or update_request['visibility'] == 'public'):
        return 'Invalid Visibility'

    group.visibility = update_request['visibility']
    group.name = update_request['groupName']
    if update_request['update_code'] != 'false':
        group.change_join_code(update_request['join_code'])
    db.session.commit()
    return "Group updated"

@app.route('/api/group/join', methods=['POST'])
@limiter.limit("10 per minute;30 per hour", key_func=user_or_ip_key)
@login_required
def join_group():
    user_id = current_user.id
    group_id = request.get_json()['groupID']
    input_code = request.get_json()['join_code']

    try:
        group_id = int(group_id)
    except:
        return "Invalid group ID"


    membership = GiftGroupMember(group_id, user_id)
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    is_member = db.session.query(GiftGroupMember).filter_by(groupID=group_id, memberID=user_id).all()

    if is_member != []:
        return "Already in group"
    else:
        if group == None:
            return "Unknown group"

        if group.visibility == 'protected' :
            if group.check_join_code(input_code):
                db.session.add(membership)
                db.session.commit()
                return "Group joined"
            else:
                return "Failed to join group"
        else:
            db.session.add(membership)
            db.session.commit()
            return "Group joined"

@app.route('/api/group/leave', methods=['POST'])
@login_required
def leave_group():
    user_id = current_user.id
    group_id = request.get_json()['groupID']

    try:
        group_id = int(group_id)
    except:
        return "Invalid group ID"

    
    membership = db.session.query(GiftGroupMember).filter_by(groupID=group_id, memberID=user_id).first()

    if membership == None:
        return "Not in group"
    else:
        db.session.delete(membership)
        db.session.commit()
        return "Group left"

@app.route('/api/group/candidates/<int:group_id>', methods=['GET'])
@login_required
def group_candidates(group_id):
    # Users of the site that are not yet in the group, optionally filtered by login (admin only)
    user_id = current_user.id
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    query = request.args.get('q', '').strip().lower()
    current_members = db.session.query(GiftGroupMember.memberID).filter(GiftGroupMember.groupID == group_id)
    candidates = db.session.query(User).filter(~User.id.in_(current_members))
    if query != '':
        candidates = candidates.filter(func.lower(User.login).contains(query, autoescape=True))
    candidates = candidates.order_by(User.login).limit(20).all()

    return jsonify({
        'status': 'OK',
        'users': [{'id': candidate.id, 'login': candidate.login} for candidate in candidates]
    })

@app.route('/api/group/member/add', methods=['POST'])
@login_required
def add_group_member():
    user_id = current_user.id
    request_data = request.get_json()

    try:
        group_id = int(request_data.get('groupID'))
        member_id = int(request_data.get('userID'))
    except (TypeError, ValueError):
        return jsonify({'status': 'Invalid request'})

    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    if group.secret_santa_active:
        return jsonify({'status': 'Stop the Secret Santa before changing the members'})

    if db.session.query(User).filter(User.id == member_id).first() is None:
        return jsonify({'status': 'User does not exist'})

    if user_in_group(member_id, group_id):
        return jsonify({'status': 'Already in group'})

    db.session.add(GiftGroupMember(group_id, member_id))
    db.session.commit()
    return jsonify({'status': 'Member added'})

@app.route('/api/group/member/remove', methods=['DELETE'])
@login_required
def remove_group_member():
    user_id = current_user.id
    request_data = request.get_json()

    try:
        group_id = int(request_data.get('groupID'))
        member_id = int(request_data.get('userID'))
    except (TypeError, ValueError):
        return jsonify({'status': 'Invalid request'})

    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    if group.secret_santa_active:
        return jsonify({'status': 'Stop the Secret Santa before changing the members'})

    memberships = db.session.query(GiftGroupMember).filter_by(groupID=group_id, memberID=member_id).all()
    if memberships == []:
        return jsonify({'status': 'Not in group'})

    for membership in memberships:
        db.session.delete(membership)

    # Exclusions involving the removed member are meaningless now
    exclusions = db.session.query(SecretSantaExclusion).filter(
        SecretSantaExclusion.groupID == group_id,
        db.or_(SecretSantaExclusion.userID == member_id, SecretSantaExclusion.excludedUserID == member_id)
    ).all()
    for exclusion in exclusions:
        db.session.delete(exclusion)

    db.session.commit()
    return jsonify({'status': 'Member removed'})

@app.route('/api/group/invite', methods=['POST'])
@limiter.limit("20 per hour;50 per day", key_func=user_or_ip_key)
@login_required
def invite_group_member():
    user_id = current_user.id
    request_data = request.get_json()

    try:
        group_id = int(request_data.get('groupID'))
    except (TypeError, ValueError):
        return jsonify({'status': 'Invalid request'})

    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    if group.secret_santa_active:
        return jsonify({'status': 'Stop the Secret Santa before changing the members'})

    clean_email = sanitize_email(request_data.get('email') or '')
    if clean_email is None:
        return jsonify({'status': 'Incorrect email format'})

    user = db.session.query(User).filter(User.email_address == clean_email).first()
    if user is not None:
        if user_in_group(user.id, group_id):
            return jsonify({'status': 'Already in group'})
        db.session.add(GiftGroupMember(group_id, user.id))
        db.session.commit()
        return jsonify({'status': 'Member added'})

    pending = db.session.query(GroupInvitation).filter(
        GroupInvitation.groupID == group_id, GroupInvitation.email == clean_email
    ).all()
    if any(invitation.is_valid() for invitation in pending):
        return jsonify({'status': 'Invitation already pending'})

    raw_token = secrets.token_urlsafe(32)
    invitation = GroupInvitation(group_id, clean_email, hash_token(raw_token))
    db.session.add(invitation)
    db.session.commit()

    invite_link = f"{cors_protocol}://{cors_host}/invite/{raw_token}"

    try:
        send_group_invitation_email(clean_email, group.name, current_user.login, invite_link)
    except Exception:
        db.session.delete(invitation)
        db.session.commit()
        return jsonify({'status': 'Failed to send the invitation email'})

    return jsonify({'status': 'Invitation sent'})

@app.route('/api/group/invitations/<int:group_id>', methods=['GET'])
@login_required
def group_invitations(group_id):
    user_id = current_user.id

    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    invitations = db.session.query(GroupInvitation).filter(
        GroupInvitation.groupID == group_id
    ).order_by(GroupInvitation.created_at).all()

    return jsonify({
        'status': 'OK',
        'invitations': [
            {'id': invitation.id, 'email': invitation.email, 'expires': date_to_string(invitation.expires_at)}
            for invitation in invitations if invitation.is_valid()
        ]
    })

@app.route('/api/group/invitation/cancel', methods=['DELETE'])
@login_required
def cancel_group_invitation():
    user_id = current_user.id
    request_data = request.get_json()

    try:
        invitation_id = int(request_data.get('invitationID'))
    except (TypeError, ValueError):
        return jsonify({'status': 'Invalid invitation'})

    invitation = db.session.query(GroupInvitation).filter(GroupInvitation.id == invitation_id).first()
    if invitation is None:
        return jsonify({'status': 'Invalid invitation'})

    group = db.session.query(GiftGroup).filter(GiftGroup.id == invitation.groupID).first()
    if group is None:
        return jsonify({'status': 'Group does not exist'})

    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'You are not an admin of the group'})

    db.session.delete(invitation)
    db.session.commit()
    return jsonify({'status': 'Invitation cancelled'})

@app.route('/api/group/delete', methods=['DELETE'])
@login_required
def delete_group():
    user_id = current_user.id
    delete_request = request.get_json()

    group_id = delete_request['groupID']

    try:
        group_id = int(group_id)
    except:
        return "Invalid group ID"


    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()

    if group == None:
        return "Group not found"
    elif group.creatorID != str(user_id):
        abort(401)
    else:
        members = db.session.query(GiftGroupMember).filter(GiftGroupMember.groupID == group.id).all()
        pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == group.id).all()
        invitations = db.session.query(GroupInvitation).filter(GroupInvitation.groupID == group.id).all()
        db.session.delete(group)
        
        for member in members:
            db.session.delete(member)
        for pair in pairs:
            db.session.delete(pair)
        for invitation in invitations:
            db.session.delete(invitation)
        db.session.commit()
        return "The group has been removed."

@app.route('/api/secret/start', methods=['POST'])
@login_required
def secret_stanta_start():
    user_id = current_user.id
    start_request = request.get_json()
    
    scheduled_date = string_to_date(start_request['date'])
    group = db.session.query(GiftGroup).filter(GiftGroup.id == start_request['groupID']).first()
    if group == None:
        return "Invalid group"

    if not(str(group.creatorID) == str(user_id)):
        return 'Only group admin can start Secret Santa'

    if group.secret_santa_active == True:
        return "Secret Santa already active"

    if scheduled_date == 'Incorrect date format':
        return 'Incorrect date format'

    users_in_group = db.session.query(GiftGroupMember).filter(GiftGroupMember.groupID == start_request['groupID']).all()
    userids = []
    for pair in users_in_group:
        userids.append(pair.memberID)
    if len(userids) < 3:
        return 'Not enough members in the group, you must have at least 3 members'
    
    try:
        status = generate_secret_pairs(userids, group.id)
        if status != 'OK':
            return status  # Return error message if constraints can't be satisfied

        group.secret_santa_active = True
        group.secret_santa_date = scheduled_date
        db.session.commit()
        
        return "Secret Santa started"

    except:
        return "Unexpected error"

@app.route('/api/secret/reschedule', methods=['POST'])
@login_required
def secret_stanta_reschedule():
    user_id = current_user.id
    schedule_request = request.get_json()
    
    scheduled_date = string_to_date(schedule_request['date'])
    group = db.session.query(GiftGroup).filter(GiftGroup.id == schedule_request['groupID']).first()
    if group == None:
        return "Invalid group"

    if group.secret_santa_active != True:
        return "You can't reschedule, no Secret Santa is started"
    if not(str(group.creatorID) == str(user_id)):
        return 'Only group admin can schedule Secret Santa'

    if scheduled_date == 'Incorrect date format':
        return 'Incorrect date format'

    group.secret_santa_date = scheduled_date
    db.session.commit()
    return "Secret Santa rescheduled"

@app.route('/api/secret/stop', methods=['POST'])
@login_required
def secret_stanta_stop():
    user_id = current_user.id
    stop_request = request.get_json()
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == stop_request['groupID']).first()
    if group == None:
        return "Invalid group"

    if not(group.secret_santa_active == True):
        return "No Secret Santa active"

    if not(str(group.creatorID) == str(user_id)):
        return 'Only group admin can stop Secret Santa'

    pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == stop_request['groupID']).all()
    for pair in pairs:
        db.session.delete(pair)

    group.secret_santa_active = False
    db.session.commit()
    return "Secret Santa stopped"

@app.route('/api/secret/mysecret/group/<int:group_id>', methods=['GET'])
@login_required
def my_secret(group_id):
    user_id = current_user.id
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    if group == None:
        return jsonify({'status': 'no group'})
    if not user_in_group(user_id, group_id):
        return jsonify({'status': 'no group'})
        
    if not(group.secret_santa_active == True):
        return jsonify({'status': 'No Secret Santa active'})
   

    pair = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == group_id, SecretSantaPair.gifterID == user_id).first()
    if pair is None:
        return jsonify({'status': 'No Secret Santa pair'})

    receiver = db.session.query(User).filter(User.id == pair.receiverID).first()
    

    data = {}

    data['date'] = date_to_string(group.secret_santa_date)

    if receiver == None:
        admin = db.session.query(User).filter(User.id == group.creatorID).first()
        data['receiverLogin'] = 'The User has been deleted, please contact your group admin : ' + admin.login
        data['status'] = 'No users'
        data['gifts'] = []
    else:
        data['receiverLogin'] = receiver.login

        gifts = db.session.query(Gift).filter(Gift.receiverID == receiver.id).all()
        gifts_list = [{
            "giftID": gift.giftID,
            "name": gift.name,
            "description": gift.description,
            "price": gift.price,
            "receiverID": gift.receiverID,
            "gifterID": gift.gifterID,
            "image_url": gift.image_url
        } for gift in gifts]
        data['gifts'] = gifts_list
        data['status'] = 'OK'
    return jsonify(data)

@app.route('/api/secret/info/group/<int:group_id>', methods=['GET'])
@login_required
def is_active(group_id):
    user_id = current_user.id
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    
    info_json = {}

    if group == None:
        return jsonify({'status': 'Invalid group'})
    if not user_in_group(user_id, group_id) and str(group.creatorID) != str(user_id):
        return jsonify({'status': 'Invalid group'})
    if group.secret_santa_active == True:
        info_json['secret_santa'] = 'true'
        info_json['date'] = date_to_string(group.secret_santa_date)
    else:
        info_json['secret_santa'] = 'false'
    return jsonify(info_json)

@app.route('/api/exclusions/group/<int:group_id>', methods=['GET'])
@login_required
def get_exclusions(group_id):
    user_id = current_user.id
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    
    if group is None:
        return jsonify({'status': 'Invalid group'})
    
    # Check if user is admin of the group
    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'Only group admin can manage exclusions'})
    
    # Get all exclusions for this group
    exclusions = db.session.query(SecretSantaExclusion).filter(SecretSantaExclusion.groupID == group_id).all()
    
    # Format exclusions for the response
    formatted_exclusions = []
    for exclusion in exclusions:
        user = db.session.query(User).filter(User.id == exclusion.userID).first()
        excluded_user = db.session.query(User).filter(User.id == exclusion.excludedUserID).first()
        
        formatted_exclusions.append({
            'id': exclusion.id,
            'userID': exclusion.userID,
            'userName': user.login if user else 'Unknown',
            'excludedUserID': exclusion.excludedUserID,
            'excludedUserName': excluded_user.login if excluded_user else 'Unknown'
        })
    
    return jsonify({
        'status': 'OK',
        'exclusions': formatted_exclusions
    })

@app.route('/api/exclusions/add', methods=['POST'])
@login_required
def add_exclusion():
    user_id = current_user.id
    request_data = request.get_json()
    
    group_id = request_data.get('groupID')
    excluded_user_id = request_data.get('excludedUserID')
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    
    if group is None:
        return jsonify({'status': 'Invalid group'})
    
    # Check if user is admin of the group
    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'Only group admin can manage exclusions'})
    
    # Check if both users are in the group
    user1_in_group = user_in_group(request_data.get('userID'), group_id)
    user2_in_group = user_in_group(excluded_user_id, group_id)
    
    if not user1_in_group or not user2_in_group:
        return jsonify({'status': 'Users must be in the group'})
    
    # Check if exclusion already exists
    existing = db.session.query(SecretSantaExclusion).filter(
        SecretSantaExclusion.groupID == group_id,
        SecretSantaExclusion.userID == request_data.get('userID'),
        SecretSantaExclusion.excludedUserID == excluded_user_id
    ).first()
    
    if existing:
        return jsonify({'status': 'Exclusion already exists'})
    
    # Create new exclusion
    exclusion = SecretSantaExclusion(
        group_id,
        request_data.get('userID'),
        excluded_user_id
    )
    
    db.session.add(exclusion)
    db.session.commit()
    
    return jsonify({'status': 'Exclusion added'})

@app.route('/api/exclusions/delete', methods=['DELETE'])
@login_required
def delete_exclusion():
    user_id = current_user.id
    request_data = request.get_json()
    
    exclusion_id = request_data.get('exclusionID')
    
    exclusion = db.session.query(SecretSantaExclusion).filter(SecretSantaExclusion.id == exclusion_id).first()
    
    if exclusion is None:
        return jsonify({'status': 'Invalid exclusion'})
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == exclusion.groupID).first()
    
    # Check if user is admin of the group
    if str(group.creatorID) != str(user_id):
        return jsonify({'status': 'Only group admin can manage exclusions'})
    
    db.session.delete(exclusion)
    db.session.commit()
    
    return jsonify({'status': 'Exclusion deleted'})

####################################################################################################
###########################################   EXECUTION   ##########################################
####################################################################################################

if __name__ == '__main__':

    with app.app_context():
        # Check if the database exists, if not, create it
        if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
            create_database(app.config['SQLALCHEMY_DATABASE_URI'])

        # Create all tables defined in the models
        db.create_all()
        apply_schema_migrations()
        log_legacy_hash_count()

        if not(server_debug):
            check_inactive_users_periodically()

    login_manager = LoginManager()
    login_manager.init_app(app)
    @login_manager.user_loader
    def load_user(session_id):
        user_id, _, token = str(session_id).partition(':')
        try:
            user = db.session.get(User, int(user_id))
        except ValueError:
            return None
        if user is None or not hmac.compare_digest(token, user.get_session_token()):
            return None
        return user
    
    if server_debug:
        app.run(host = server_host, port = server_port, debug = server_debug)
    else:
        serve(app, host=server_host, port=server_port, max_request_body_size=1024 * 1024)
