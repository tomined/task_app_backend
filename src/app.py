from flask import Flask, jsonify, request,session
from werkzeug.security import generate_password_hash, check_password_hash
from config import users_collection
from utils.regex_patterns import password_pattern, email_pattern
from utils.session_expiration import set_session_expiration
from dotenv import load_dotenv
import datetime
import re
import os 
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# ---------------------------------------------------------------------------------------------------------
# Rejestracja użytkownika
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        email = request.json['email']
        hashed_password = generate_password_hash(password)

        if users_collection.find_one({'username': username}):
            error_response = jsonify({
                'message': 'Użytkownik o podanej nazwie już istnieje',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Sprawdzenie czy email istnieje już w bazie
        if users_collection.find_one({'email': email}):
            error_response = jsonify({
                'message': 'Konto o podanym adresie email już istnieje',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Sprawdzenie hasła za pomocą regular expression
        if re.match(password_pattern, password) is None:
            error_response = jsonify({
                'message': 'Hasło musi zawierać małą, dużą literę, cyfrę i minimum 5 znaków',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response
        
        # Sprawdzenie emaila za pomocą regular expression
        if re.match(email_pattern, email) is None:
            error_response = jsonify({
                'message': 'Niepoprawny adres email',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Dodanie nowego dokumentu do bazy
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email
        })

        # Wyświetlenie czegoś po pomyślnym wyślaniu zapytania o rejestrację
        response = jsonify({
            'username': username,
            'password': hashed_password,
            'email': email
        })
        response.status_code = 201

        return response
    

#-------------------------------------------------------------------------------
# Logowanie
@app.route('/login',methods=['POST'])
def login():
     password = request.json['password']
     email = request.json['email']

     user = users_collection.find_one({'email':email})

     if user and check_password_hash(user['password'], password):
         expiration = set_session_expiration(app)
         session['email'] = user['email']
         session['date'] = (datetime.datetime.now() + expiration).strftime('%H:%M:%S')
    
         response = jsonify({
             'message':'Poprawnie zalogowano',
             'ok':True,
             'status':200
         })
         response.status_code = 200
         return response
     
     error_response = jsonify({
        'message': 'Błędny email lub hasło',
        'ok': False,
        'status': 403
     })
     error_response.status_code = 403
     return error_response

