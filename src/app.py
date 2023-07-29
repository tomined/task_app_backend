from flask import Flask, jsonify, request 
from werkzeug.security import generate_password_hash
from config import users_collection

app = Flask(__name__)


# Rejestracja użytkownika
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        email = request.json['email']
        hashed_password = generate_password_hash(password)

        if users_collection.find_one({'username': username}):
             return 'Użytkownik o podanej nazwie już istnieje'
        
        if users_collection.find_one({'email':email}):
             return 'Konto o podanym adresie email już istnieje'

        # Dodanie nowego dokumentu do bazy
        users_collection.insert_one({
            'username':username,
            'password':hashed_password,
            'email':email
        })

        # Wyświetlenie czegoś po pomyślnym wyślaniu zapytania o rejestrację
        response = jsonify({
            'username':username,
            'password':hashed_password,
            'email':email
        })
        response.status_code = 201

        return response
        
