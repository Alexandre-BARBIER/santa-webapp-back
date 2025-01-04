####################################################################################################
###########################################   IMPORTS   ############################################
####################################################################################################
import os
import re
import json
import secrets
import string
from waitress import serve
import random

from threading import Timer

from argon2 import PasswordHasher, exceptions

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy_utils import database_exists, create_database
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flasgger import Swagger

from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

# Extract Password Security configuration
PEPPER = os.environ['USER_PEPPER']
GROUP_PEPPER = os.environ['GROUP_PEPPER']

# Extract CORS configuration
cors_host = os.environ['CORS_HOST']

if server_debug:
    cors_protocol = 'http'
else:
    cors_protocol = 'https'

# Extract Account Inactivity Policy Configuration
max_inactivity_allowed = int(os.environ['MAX_INACTIVITY'])
check_interval = int(os.environ['INACTIVITY_CHECK'])


####################################################################################################
##########################################   APP CONFIG  ###########################################
####################################################################################################

app = Flask(__name__)
CORS(app)

CORS(
    app,
    resources={
        r"/*": {
            "origins": cors_protocol + "://" + cors_host,
            "supports_credentials": True,
            "Access-Control-Allow-Credentials": True,
        }
    },
)

def generate_secret_key(length=24):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

app.config['SQLALCHEMY_DATABASE_URI'] = 'mariadb+mariadbconnector://' + username + ':' + password + '@' + db_host + '/' + db_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = generate_secret_key()

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

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

swagger = Swagger(app)

####################################################################################################
##########################################   PEPPERING   ###########################################
####################################################################################################

def encrypt_data(data, key):
    iv = secrets.token_bytes(16)  # Initialization vector
    key = key.encode()
    data = data.encode()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(ciphertext, key):
    iv = ciphertext[:16]
    key = key.encode('utf-8')
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

####################################################################################################
##############################################   DB   ##############################################
####################################################################################################

class User(UserMixin, db.Model):
    
    # class for the user table of the database
    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    login = db.Column(db.String(100))
    hashed_and_peppered_password = db.Column(db.LargeBinary)
    birthdate = db.Column(db.Date())
    email_address = db.Column(db.String(100))
    creation_date = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)

    def __init__(self,first_name, surname, login, password, birthdate, email_address):
        self.first_name = first_name
        self.surname = surname
        self.login = login
        argon_init = PasswordHasher()
        hashed_password = argon_init.hash(password + PEPPER)
        self.hashed_and_peppered_password = encrypt_data(hashed_password, PEPPER)
        self.birthdate = birthdate
        self.email_address = email_address
        self.creation_date = datetime.now()
        self.last_login = datetime.now()

    def update(self,first_name, surname, login, birthdate, email_address):
        self.first_name = first_name
        self.surname = surname
        self.login = login
        self.birthdate = birthdate
        self.email_address = email_address


    def check_password(self,password_to_check):
        argon_init = PasswordHasher()
        try:
            hashed_password = decrypt_data(self.hashed_and_peppered_password, PEPPER)
            argon_init.verify(hashed_password, password_to_check + PEPPER)
            return True
        except exceptions.VerifyMismatchError:
            return False

    def update_password(self, new_password):
        argon_init = PasswordHasher()
        hashed_password = argon_init.hash(new_password + PEPPER)
        self.hashed_and_peppered_password = encrypt_data(hashed_password, PEPPER)
    
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
        argon_init = PasswordHasher()
        hashed_code = argon_init.hash(join_code + GROUP_PEPPER)
        self.join_code = encrypt_data(hashed_code, GROUP_PEPPER)
        if len(join_code) == 1:
            self.hint = join_code
        else:
            self.hint = join_code[:1] + '*' * (len(join_code) - 2) + join_code[-1:]
        self.creatorID = creatorID
        self.secret_santa_active = False
        self.secret_santa_date = datetime.now()

    def check_join_code(self,code_to_check):
        argon_init = PasswordHasher()
        try:
            hashed_code = decrypt_data(self.join_code, GROUP_PEPPER)
            argon_init.verify(hashed_code, code_to_check + GROUP_PEPPER)
            return True
        except exceptions.VerifyMismatchError:
            return False
    
    def change_join_code(self,new_join_code):
        argon_init = PasswordHasher()
        hashed_code = argon_init.hash(new_join_code + GROUP_PEPPER)
        self.join_code = encrypt_data(hashed_code, GROUP_PEPPER)
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

def generate_secret_pairs(users, group):

    first_user = users[0]
    receiver = users[0]
    while users != []:
        users.remove(receiver)
        if len(users) != 0:
            gifter = random.choice(users)
        else:
            gifter = first_user
        pair = SecretSantaPair(receiver,gifter,group)
        db.session.add(pair)
        receiver = gifter
    db.session.commit()

    return 'OK'
    

####################################################################################################
########################################  INACTIVE USERS   #########################################
####################################################################################################

def delete_inactive_users():
    threshold = datetime.now() - timedelta(days = max_inactivity_allowed)
    inactive_users = db.session.query(User).filter(User.last_login <= threshold).all()
    for user in inactive_users:
        db.session.delete(user)
    db.session.commit()

def check_inactive_users_periodically():    
    delete_inactive_users()
    # Schedule the next execution of this function
    Timer(check_interval, check_inactive_users_periodically).start()


####################################################################################################
#############################################   ROUTE   ############################################
####################################################################################################

@app.route('/api/logout')
@login_required
def logout():
    """
    Logs the user out.
    ---
    tags:
      - Authentication
    responses:
      200:
        description: User logged out successfully.
    """
    logout_user()
    return "Logged out"

@app.route('/api/login', methods=['POST'])
def login():
    """
    Logs in a user.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              login:
                type: string
                example: "user123"
              password:
                type: string
                example: "password123"
              remember_me:
                type: string
                example: "true"
    responses:
      200:
        description: User logged in successfully.
      401:
        description: Incorrect login or password.
    """
    login = request.get_json()['login']
    password = request.get_json()['password']
    
    remember_me_string = request.get_json()['remember_me']
    
    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False


    user = db.session.query(User).filter(User.login == login).first()
    if not user:
        user = db.session.query(User).filter(User.email_address == login).first()

    if not user or not user.check_password(password):
        return "Login ou mot de passe incorrect"
    else:
        user.update_last_login()
        db.session.commit()
        login_user(user, remember=remember_me)
        return "Vous êtes connecté!"
    

@app.route('/api/signup', methods = ['POST'])
def signup():
    """
    Signs up a new user.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              first_name:
                type: string
                example: "John"
              surname:
                type: string
                example: "Doe"
              login:
                type: string
                example: "johndoe"
              password:
                type: string
                example: "password123"
              birthdate:
                type: string
                format: date
                example: "1990-01-01"
              email_address:
                type: string
                example: "johndoe@example.com"
              remember_me:
                type: string
                example: "true"
    responses:
      200:
        description: User signed up and logged in successfully.
      400:
        description: Validation error or incorrect format.
    """
    signup_request = request.get_json()
    dbentry_user = db.session.query(User).filter(User.login == signup_request['login']).first()
    
    clean_email = sanitize_email(signup_request['email_address'])
    dbentry_email = db.session.query(User).filter(User.email_address == clean_email).first()
    

    remember_me_string = request.get_json()['remember_me']
    
    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False

    if dbentry_user == None:
        if dbentry_email == None:
            birthdate = string_to_date(signup_request['birthdate'])
            if birthdate != "Incorrect date format" and clean_email:
                user = User(signup_request['first_name'], signup_request['surname'], signup_request['login'], signup_request['password'], birthdate, clean_email)
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=remember_me)
                return "Inscription réussie"
            else:
                if birthdate == "Incorrect date format":
                    return "Incorrect date format"
                else:
                    return 'Incorrect email format'
        else:
            return "Email already used"
    else:
        return "Login already used"

@app.route('/api/forgotpassword', methods=['POST'])
def forgotpassword():
    """
    Resets the user's password and sends an email with the new password.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              email_address:
                type: string
                example: "johndoe@example.com"
    responses:
      200:
        description: Temporary password sent via email.
      400:
        description: Validation error.
      500:
        description: Internal server error.
    """
    forgot_request = request.get_json()

    user = db.session.query(User).filter(User.email_address==forgot_request['email_address']).first()
    
    char_pool = string.ascii_letters + string.digits
    password = [
        random.choice(string.ascii_uppercase),  # At least one uppercase letter
        random.choice(string.ascii_lowercase),  # At least one lowercase letter
        random.choice(string.digits),          # At least one digit
    ]
    password += random.choices(char_pool, k=10 - len(password))

    random.shuffle(password)

    temporary_password = ''.join(password)

    user.update_password(temporary_password)
    db.session.commit()

    try:
        recipient = forgot_request['email_address']
        subject = 'Reset Password Santa'
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <table style="width: 100%; max-width: 600px; margin: 0 auto; border-collapse: collapse; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background-color: #f4f4f4; border-bottom: 1px solid #ddd;">
                        <th style="padding: 15px; text-align: left;">
                            <h2 style="margin: 0; color: #333;">Password Reset Confirmation</h2>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="padding: 20px;">
                            <p>Dear {user.first_name} {user.surname},</p>
                            <p>We have successfully processed your request to reset your password. Below are your updated login credentials:</p>
                            <table style="margin: 20px 0; width: 100%;">
                                <tr>
                                    <td style="font-weight: bold; color: #555;">Username:</td>
                                    <td>{user.login}</td>
                                </tr>
                                <tr>
                                    <td style="font-weight: bold; color: #555;">Temporary Password:</td>
                                    <td><strong>{temporary_password}</strong></td>
                                </tr>
                            </table>
                            <p>For your security, please log in to your account and update your password as soon as possible. You can do so by following these steps:</p>
                            <ol>
                                <li>Log in to your account using the temporary password provided.</li>
                                <li>Click on the <strong>"Change Password"</strong> button.</li>
                                <li>Enter a new, secure password of your choice and save the changes.</li>
                            </ol>
                            <p style="color: #888;">If you didn’t request a password reset or believe this message was sent in error, please contact me immediately at <a href="{os.environ['MAIL_USER']}" style="color: #007BFF;">{os.environ['MAIL_USER']}</a></p>
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

        # Validate required fields
        if not recipient or not subject or not body:
            return jsonify({"error": "'recipient', 'subject', and 'body' are required fields"}), 400

        # Create and send the email
        msg = Message(subject, recipients=[recipient], html=body)
        mail.send(msg)

        return jsonify({"message": "Email sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/changepassword', methods = ['PUT'])
@login_required
def changepassword():
    """
    Changes the user's password.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              old_password:
                type: string
                example: "oldpassword123"
              new_password:
                type: string
                example: "newpassword123"
    responses:
      200:
        description: Password updated successfully.
      400:
        description: Validation error or incorrect current password.
    """
    user_id = current_user.id
    user = db.session.query(User).filter(User.id==user_id).first()
    change_password_request = request.get_json()
    
    if user.check_password(change_password_request['new_password']):
        return "No change made"
    elif not(user.check_password(change_password_request['old_password'])):
        return "No change made, Wrong Password"
    else :
        current_user.update_password(change_password_request['new_password'])
        db.session.commit()
        return "Update Password"

@app.route('/api/user/delete', methods = ['DELETE'])
@login_required
def delete_user():
    """
    Deletes the current user's account.
    ---
    tags:
      - User
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              password:
                type: string
                example: "password123"
    responses:
      200:
        description: User account deleted successfully.
      400:
        description: Incorrect password.
    """
    user_id = current_user.id
    user = db.session.query(User).filter(User.id==user_id).first()
    delete_request = request.get_json()
    if not(user.check_password(delete_request['password'])):
        return "Wrong password"
    
    admin_groups = db.session.query(GiftGroup).filter(GiftGroup.creatorID == user_id).all()

    for group in admin_groups:
        members = db.session.query(GiftGroupMember).filter(GiftGroupMember.groupID == group.id).all()
        pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == group.id).all()
        db.session.delete(group)
        
        for member in members:
            db.session.delete(member)
        for pair in pairs:
            db.session.delete(pair)

    memberships = db.session.query(GiftGroupMember).filter(GiftGroupMember.memberID == user_id).all()

    for membership in memberships:
        db.session.delete(membership)

    gifter_pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.gifterID == user.id).all()
    for pair in gifter_pairs:
        pair.gifterID = -1
    receiver_pairs = db.session.query(SecretSantaPair).filter(SecretSantaPair.receiverID == user.id).all()
    for pair in receiver_pairs:
        pair.receiverID = -1
    

    db.session.delete(user)

    db.session.commit()
    
    logout_user()
    
    return "User deleted"

@app.route('/api/changeprofile', methods = ['PUT'])
@login_required
def changeprofile():
    """
    Updates the current user's profile.
    ---
    tags:
      - User
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              first_name:
                type: string
                example: "John"
              surname:
                type: string
                example: "Doe"
              login:
                type: string
                example: "johndoe"
              birthdate:
                type: string
                format: date
                example: "1990-01-01"
              email_address:
                type: string
                example: "johndoe@example.com"
    responses:
      200:
        description: Profile updated successfully.
      400:
        description: Validation error or login/email already used.
    """
    change_profile_request = request.get_json()
    user = current_user
    dbentry_user = User.query.filter_by(login=change_profile_request['login']).all()

    clean_email = sanitize_email(change_profile_request['email_address'])
    dbentry_email = db.session.query(User).filter(User.email_address == clean_email).all()
    

    if dbentry_user == [] or user.login == change_profile_request['login']:
        if dbentry_email == [] or user.email_address == change_profile_request['email_address']:
            if change_profile_request['birthdate'] == "":
                birthdate = user.birthdate
            else:
                birthdate = string_to_date(change_profile_request['birthdate'])
            if change_profile_request['email_address'] == "":
                email = user.email_address
            else:
                email = change_profile_request['email_address']
            email = sanitize_email(email)
            if birthdate != "Incorrect date format" and email:
                current_user.update(change_profile_request['first_name'], change_profile_request['surname'], change_profile_request['login'], birthdate, email)
                db.session.commit()
                return "Updated Profile"
            else:
                return "Incorrect format"
        else:
            return "Email already used"
    else:
        return "Login already used"

@app.route('/api/profile/<int:userid>', methods = ['GET'])
@login_required
def profile(userid):
    """
    Retrieves the profile information of a user.
    ---
    tags:
      - User
    parameters:
      - name: userid
        in: path
        required: true
        schema:
          type: integer
        description: ID of the user whose profile is being retrieved.
    responses:
      200:
        description: User profile retrieved successfully.
        content:
          application/json:
            schema:
              type: object
              properties:
                first_name:
                  type: string
                surname:
                  type: string
                login:
                  type: string
                email_address:
                  type: string
                birthdate:
                  type: string
                  format: date
      404:
        description: User not found.
    """
    dbentry = db.session.query(User).filter(User.id == userid).first()
    if dbentry != None:
        record = {"first_name":dbentry.first_name,"surname":dbentry.surname,"login":dbentry.login,"email_address":""}
        if in_same_group(userid,current_user.id):
            record["birthdate"] = date_to_string(dbentry.birthdate)
        if str(userid) == str(current_user.id):
            record["birthdate"] = date_to_string(dbentry.birthdate)
            record["email_address"] = dbentry.email_address
        record_json = jsonify(record)
        return record_json
    else:
        abort(404)

@app.route('/api/myprofile', methods = ['GET'])
@login_required
def myprofile():
    """
    Retrieves the current user's ID.
    ---
    tags:
      - User
    responses:
      200:
        description: User ID retrieved successfully.
        content:
          application/json:
            schema:
              type: object
              properties:
                user_id:
                  type: integer
    """
    record_json = jsonify({"user_id":current_user.id})
    return record_json


@app.route('/api/mygifts', methods=['GET'])
@login_required
def mygifts():
    """
    Retrieves a list of gifts for the current user.
    ---
    tags:
      - Gifts
    responses:
      200:
        description: List of gifts retrieved successfully.
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  giftID:
                    type: integer
                  name:
                    type: string
                  description:
                    type: string
                  price:
                    type: number
                  receiverID:
                    type: integer
                  image_url:
                    type: string
    """
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
    """
    Retrieves gifts in a specified group.
    ---
    tags:
      - Gifts
    parameters:
      - name: group_id
        in: path
        required: true
        schema:
          type: integer
        description: ID of the gift group.
    responses:
      200:
        description: List of gifts in the group retrieved successfully.
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  giftID:
                    type: integer
                  name:
                    type: string
                  description:
                    type: string
                  price:
                    type: number
                  receiverID:
                    type: integer
                  receiverLogin:
                    type: string
                  gifterID:
                    type: integer
                  image_url:
                    type: string
      401:
        description: User not authorized to view the group's gifts.
    """
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
    """
    Adds a new gift for the current user.
    ---
    tags:
      - Gifts
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              name:
                type: string
                example: "Book"
              description:
                type: string
                example: "A fantasy novel."
              price:
                type: number
                example: 25.99
    responses:
      200:
        description: Gift added successfully.
      400:
        description: Invalid price.
    """
    userid = current_user.id
    add_request = request.get_json()
    try:
        price = float(add_request['price'])
    except:
        return 'Incorrect Price'
    gift = Gift(add_request['name'], add_request['description'], price,userid,'')
    db.session.add(gift)
    db.session.commit()
    return "Gift Added"

@app.route('/api/gift/select', methods = ['POST'])
@login_required
def select_gift():
    """
    Marks a gift as selected by the current user.
    ---
    tags:
      - Gifts
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              gift_id:
                type: integer
                example: 123
    responses:
      200:
        description: Gift selected successfully.
      401:
        description: User not in the same group as the gift receiver.
      404:
        description: Gift not found.
    """
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
    """
    Unmarks a gift as selected by the current user.
    ---
    tags:
      - Gifts
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              gift_id:
                type: integer
                example: 123
    responses:
      200:
        description: Gift unselected successfully.
      404:
        description: Gift not found.
    """
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
    """
    Deletes a gift owned by the current user.
    ---
    tags:
      - Gifts
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              gift_id:
                type: integer
                example: 123
    responses:
      200:
        description: Gift deleted successfully.
      404:
        description: Gift not found.
      400:
        description: User not authorized to delete the gift.
    """
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
    """
    Retrieves a list of groups the current user belongs to.
    ---
    tags:
      - Groups
    responses:
      200:
        description: List of user's groups retrieved successfully.
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
                  secret_santa:
                    type: string
    """
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

    """
    Get all public groups.
    ---
    tags:
      - Groups
    responses:
      200:
        description: A list of public groups
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    example: 1
                  name:
                    type: string
                    example: Group Name
    """
    public_groups = db.session.query(GiftGroup).filter(GiftGroup.visibility != 'protected').all()
    groups = []
    for group in public_groups:
        group_data = {'id': group.id, 'name': group.name}
        groups.append(group_data)
    return jsonify(groups)

@app.route('/api/group/create', methods=['POST'])
@login_required
def create_group():
    """
    Create a new group.
    ---
    tags:
      - Groups
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupName:
                type: string
                example: Family Group
              visibility:
                type: string
                enum: [protected, public]
                example: public
              join_code:
                type: string
                example: secret123
    responses:
      200:
        description: Group created successfully
      400:
        description: Invalid visibility
    """
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
    """
    Get groups administered by the current user.
    ---
    tags:
      - Groups
    responses:
      200:
        description: List of groups administered by the user
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    example: 1
                  name:
                    type: string
                    example: My Group
                  visibility:
                    type: string
                    enum: [protected, public]
                    example: public
                  join_code:
                    type: string
                    example: h***2
                  secret_santa:
                    type: string
                    example: Yes
    """
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
    """
    Get detailed information about a group.
    ---
    tags:
      - Groups
    parameters:
      - name: group_id
        in: path
        required: true
        schema:
          type: integer
        description: ID of the group
    responses:
      200:
        description: Group information
        content:
          application/json:
            schema:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                name:
                  type: string
                  example: Group Name
                visibility:
                  type: string
                  enum: [protected, public]
                  example: public
                join_code:
                  type: string
                  example: j****3
                members:
                  type: array
                  items:
                    type: string
                    example: user123
                status:
                  type: string
                  example: OK
    """
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
    logins = []
    for userid in userids:
        user = db.session.query(User).filter(User.id==userid).first()
        logins.append(user.login)
    group_json['members'] = logins
    group_json['status'] = 'OK'
    return jsonify(group_json)

@app.route('/api/group/update', methods=['POST'])
@login_required
def update_group():
    """
    Update a group's details.
    ---
    tags:
      - Groups
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
              groupName:
                type: string
                example: Updated Group Name
              visibility:
                type: string
                enum: [protected, public]
                example: public
              update_code:
                type: string
                enum: [true, false]
                example: false
              join_code:
                type: string
                example: new_code123
    responses:
      200:
        description: Group updated successfully
      400:
        description: Invalid visibility
      404:
        description: Group not found
      403:
        description: User is not the admin of the group
    """
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
@login_required
def join_group():
    """
    Join a group using a join code.
    ---
    tags:
      - Groups
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
              join_code:
                type: string
                example: join123
    responses:
      200:
        description: Group joined successfully
      400:
        description: Invalid group ID
      404:
        description: Group not found
      403:
        description: Failed to join group (invalid join code or already a member)
    """
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
    """
    Leave a group.
    ---
    tags:
      - Groups
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
    responses:
      200:
        description: Successfully left the group
      404:
        description: Not a member of the group
    """
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

@app.route('/api/group/delete', methods=['DELETE'])
@login_required
def delete_group():
    """
    Delete a group created by the current user.
    ---
    tags:
      - Groups
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
    responses:
      200:
        description: The group has been removed successfully
      400:
        description: Invalid group ID or group not found
      401:
        description: User is not authorized to delete the group
    """
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
        db.session.delete(group)
        
        for member in members:
            db.session.delete(member)
        for pair in pairs:
            db.session.delete(pair)
        db.session.commit()
        return "The group has been removed."

@app.route('/api/secret/start', methods=['POST'])
@login_required
def secret_stanta_start():
    """
    Start a Secret Santa event for a group.
    ---
    tags:
      - Secret Santa
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
              date:
                type: string
                format: date
                example: 2024-12-25
    responses:
      200:
        description: Secret Santa started successfully
      400:
        description: Invalid input (e.g., invalid group, incorrect date format)
      403:
        description: Only the group admin can start Secret Santa
      409:
        description: Secret Santa already active or insufficient members
    """
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
            return 'Pairs couldn\'t be generated'

        group.secret_santa_active = True
        group.secret_santa_date = scheduled_date
        db.session.commit()
        return "Secret Santa started"
    except:
        return "Unexpected error"

@app.route('/api/secret/reschedule', methods=['POST'])
@login_required
def secret_stanta_reschedule():
    """
    Reschedule the Secret Santa event for a group.
    ---
    tags:
      - Secret Santa
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
              date:
                type: string
                format: date
                example: 2024-12-30
    responses:
      200:
        description: Secret Santa rescheduled successfully
      400:
        description: Invalid input (e.g., incorrect date format)
      403:
        description: Only the group admin can reschedule Secret Santa
      409:
        description: No active Secret Santa to reschedule
    """
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
    """
    Stop the Secret Santa event for a group.
    ---
    tags:
      - Secret Santa
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              groupID:
                type: integer
                example: 1
    responses:
      200:
        description: Secret Santa stopped successfully
      400:
        description: Invalid input (e.g., non-existent group)
      403:
        description: Only the group admin can stop Secret Santa
      409:
        description: No active Secret Santa to stop
    """
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
    """
    Get the Secret Santa recipient for the current user in a specific group.
    ---
    tags:
      - Secret Santa
    parameters:
      - name: group_id
        in: path
        required: true
        schema:
          type: integer
        description: ID of the group
    responses:
      200:
        description: Recipient and gift details
        content:
          application/json:
            schema:
              type: object
              properties:
                date:
                  type: string
                  format: date
                  example: 2024-12-25
                receiverLogin:
                  type: string
                  example: recipient_user123
                gifts:
                  type: array
                  items:
                    type: object
                    properties:
                      giftID:
                        type: integer
                        example: 101
                      name:
                        type: string
                        example: Toy Car
                      description:
                        type: string
                        example: A cool toy car for kids
                      price:
                        type: number
                        format: float
                        example: 29.99
                      receiverID:
                        type: integer
                        example: 45
                      gifterID:
                        type: integer
                        example: 23
                      image_url:
                        type: string
                        example: http://example.com/images/toy-car.jpg
                status:
                  type: string
                  example: OK
    """
    user_id = current_user.id
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    if group == None:
        return jsonify({'status': 'no group'})
        
    if not(group.secret_santa_active == True):
        return jsonify({'status': 'No Secret Santa active'})
   

    pair = db.session.query(SecretSantaPair).filter(SecretSantaPair.groupID == group_id, SecretSantaPair.gifterID == user_id).first()

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

    """
    Check if a Secret Santa event is active for a specific group.
    ---
    tags:
      - Secret Santa
    parameters:
      - name: group_id
        in: path
        required: true
        schema:
          type: integer
        description: ID of the group
    responses:
      200:
        description: Secret Santa status for the group
        content:
          application/json:
            schema:
              type: object
              properties:
                secret_santa:
                  type: string
                  example: true
                date:
                  type: string
                  format: date
                  example: 2024-12-25
    """
    user_id = current_user.id
    
    group = db.session.query(GiftGroup).filter(GiftGroup.id == group_id).first()
    
    info_json = {}

    if group == None:
        return jsonify({'status': 'Invalid group'})
    if group.secret_santa_active == True:
        info_json['secret_santa'] = 'true'
        info_json['date'] = date_to_string(group.secret_santa_date)
    else:
        info_json['secret_santa'] = 'false'
    return jsonify(info_json)

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

        if not(server_debug):
            check_inactive_users_periodically()

    login_manager = LoginManager()
    login_manager.init_app(app)
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
    
    if server_debug:
        app.run(host = server_host, port = server_port, debug = server_debug)
    else:
        serve(app, host=server_host, port=server_port)
