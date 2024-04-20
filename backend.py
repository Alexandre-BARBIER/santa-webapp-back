####################################################################################################
###########################################   IMPORTS   ############################################
####################################################################################################
import os
import re
import json
import secrets
import string
from waitress import serve

from threading import Timer

from argon2 import PasswordHasher, exceptions

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy_utils import database_exists, create_database
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

####################################################################################################
#############################################   INIT   #############################################
####################################################################################################

def load_config(file_path):
    with open(file_path, 'r') as f:
        config = json.load(f)
    return config

config = load_config('config.json')

# Extract database configuration
db_config = config['database']
username = db_config['username']
password = db_config['password']
db_host = db_config['host']
db_port = db_config['port']
db_name = db_config['db_name']

# Extract Flask Server configuration
server_config = config['flask_server']
server_host = server_config['host']
server_port = server_config['port']
server_debug = server_config["debug"] == "True"

# Extract Password Security configuration
security_config = config['security']
PEPPER = security_config['pepper']
GROUP_PEPPER = security_config['group_pepper']

# Extract CORS configuration
cors_config = config['cors_config']
cors_host = cors_config['host']
cors_port = cors_config['port']

# Extract Account Inactivity Policy Configuration
inactivity_policy_config = config['inactivity_policy']
max_inactivity_allowed = inactivity_policy_config['max_inactivity']
check_interval = inactivity_policy_config['check_interval']


####################################################################################################
##########################################   APP CONFIG  ###########################################
####################################################################################################

app = Flask(__name__)
CORS(app)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "https://" + cors_host,
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
app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
####################################################################################################
##########################################   PEPPERING   ###########################################
####################################################################################################

def encrypt_data(data, key):
    iv = os.random(16)  # Initialization vector
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

    def __init__(self, name, visibility, join_code, creatorID):
        self.name = name
        self.visibility = visibility
        argon_init = PasswordHasher()
        hashed_code = argon_init.hash(join_code + GROUP_PEPPER)
        self.join_code = encrypt_data(hashed_code, GROUP_PEPPER)
        self.hint = join_code[:1] + '*' * (len(join_code) - 2) + join_code[-1:]
        self.creatorID = creatorID

    def check_join_code(self,code_to_check):
        argon_init = PasswordHasher()
        try:
            hashed_code = decrypt_data(self.join_code, GROUP_PEPPER)
            argon_init.verify(hashed_code, code_to_check + GROUP_PEPPER)
            return True
        except exceptions.VerifyMismatchError:
            return False


class GiftGroupMember(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    groupID = db.Column(db.Integer)
    memberID = db.Column(db.Integer)

    def __init__(self, groupID, memberID):
       self.groupID = groupID
       self.memberID = memberID


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
    logout_user()
    return "Logged out"

@app.route('/api/login', methods=['POST'])
def login():
    login = request.get_json()['login']
    password = request.get_json()['password']
    
    remember_me_string = request.get_json()['remember_me']
    
    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False


    user = db.session.query(User).filter(User.login == login).first()

    if not user or not user.check_password(password):
        return "Login ou mot de passe incorrect"
    else:
        user.update_last_login()
        db.session.commit()
        login_user(user, remember=remember_me)
        return "Vous êtes connecté!"
    

@app.route('/api/signup', methods = ['POST'])
def signup():
    signup_request = request.get_json()
    dbentry = db.session.query(User).filter(User.login == signup_request['login']).first()

    remember_me_string = request.get_json()['remember_me']
    
    if remember_me_string == "true":
        remember_me = True
    else:
        remember_me = False

    if dbentry == None:
        birthdate = string_to_date(signup_request['birthdate'])
        clean_email = sanitize_email(signup_request['email_address'])
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
        return "Login already used"

@app.route('/api/changepassword', methods = ['PUT'])
@login_required
def changepassword():
    user_login = current_user.login
    user = User.query.filter_by(login=user_login).first()
    change_password_request = request.get_json()
    if user.check_password(change_password_request['new_password']):
        return "No change made"
    elif not(user.check_password(change_password_request['old_password'])):
        return "No change made, Wrong Password"
    else :
        current_user.update_password(change_password_request['old_password'], change_password_request['new_password'])
        db.session.commit()
        return "Update Password"

@app.route('/api/changeprofile', methods = ['PUT'])
@login_required
def changeprofile():
    change_profile_request = request.get_json()
    user = current_user
    dbentry = User.query.filter_by(login=change_profile_request['login']).all()

    if dbentry == [] or user.login == change_profile_request['login']:
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
        return "Login already used"

@app.route('/api/profile/<int:userid>', methods = ['GET'])
@login_required
def profile(userid):
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
        groups.append({"id": group.id, "name": group.name})
    groups = sorted(groups, key=lambda x: x['id'])
    return jsonify(groups)

@app.route('/api/group/all', methods=['GET'])
@login_required
def show_groups():
    public_groups = db.session.query(GiftGroup).filter(GiftGroup.visibility != 'protected').all()
    groups = []
    for group in public_groups:
        group_data = {'id': group.id, 'name': group.name}
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
    group_list = [{
        "id" : group.id,
        "name" : group.name,
        "visibility" : group.visibility,
        "join_code" : group.hint
    } for group in groups_administred]

    return jsonify(group_list)


@app.route('/api/group/join', methods=['POST'])
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
        db.session.delete(group)
        
        for member in members:
            db.session.delete(member)
        db.session.commit()
        return "The group has been removed."

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