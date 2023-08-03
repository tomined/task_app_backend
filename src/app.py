from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from config import users_collection
from utils.regex_patterns import password_patterns, email_pattern
from utils.session_expiration import set_session_expiration
from dotenv import load_dotenv
from utils.get_response import get_response
from flask_cors import CORS
import datetime
import re
import os
load_dotenv()

app = Flask(__name__)

# Zabezpiecznie przed niechcianym dostępem
cors = CORS(app, supports_credentials=True)
app.config['CORS_HEADERS'] = 'Content-Type'

# Dodanie dla aplikacji sekretnego klucza potrzebnego do sesji
app.secret_key = os.getenv("SECRET_KEY")

# Wygaśnięcie sesji
app.permanent_session_lifetime = datetime.timedelta(minutes=30)

#---------------------------------------------------------------------------------
# Rejestracja uzytkownika
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        email = request.json['email']
        hashed_password = generate_password_hash(password)

        # Kontrola unikalności nazwy uzytkownika
        if users_collection.find_one({'username' : username}):
            return get_response('Użytkownik o podanej nazwie już istnieje',False,500)
        
        # Kontrola unikalności nazwy emaila
        if users_collection.find_one({'email': email}):
            return get_response('Konto o podanym adresie już istnieje',False,500)
        
        # Sprawdzenie hasła za pomocą regular expressions
        if re.match(password_patterns, password) is None:
            return get_response('Hasło musi zawierać małą, dużą literę, cyfrę i minimum 5 znaków',False,500)

        # Sprawdzenie maila za pomocą regular expressions
        if re.match(email_pattern, email) is None:
            return get_response('Niepoprawny email',False,500)

        # Dodanie nowego dokumentu do bazy
        users_collection.insert_one({
            'username' :username,
            'password' :hashed_password,
            'email' :email
        })

        # Wyświetlenie czegoś po pomyślnym wysłaniu zapytania o rejestrację
        new_user = {
            'username' :username,
            'password' :hashed_password,
            'email' :email
        }
        return get_response("Utworzono konto",True,201,new_user)
    
#---------------------------------------------------------------------------------
# Logowanie
@app.route('/login', methods=['POST'])
def login():
    password = request.json['password']
    email = request.json['email']

    user = users_collection.find_one({'email':email})

    if user and check_password_hash(user['password'], password):
        expiration = set_session_expiration(app)
        session['email'] = user['email']
        session['date'] = (datetime.datetime.now() + expiration).strftime('%H:%M:%S')

        return get_response("Poprawnie zalogowano",True,200)

    return get_response('Błędny email lub hasło',False,403)

#---------------------------------------------------------------------------------
# Panel użytkownika
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'email' in session:
        user = users_collection.find_one({'email':session['email']})

        return get_response('Zalogowano jako ' + user['username'],True,200,{'email':user['email'], 'username':user['username']})
    else:
        return get_response("Odmowa dostepu",False,403)
    
# Wylogowanie
@app.route('/logout')
def logout():
    session.pop('email',None)
    session.pop('date', None)

    return get_response("Pomyslnie wylogowano",True,200)


# Wyświetlenie wszystkich userów
@app.route('/get-users')
def get_users():
    users = users_collection.find({},{'_id':0})
    return jsonify(list(users))