from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import time
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import numpy as np
import base64
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Sreekar@2004",
    "database": "biometric_auth"
}

# RSA Key Persistence
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def load_or_generate_keys():
    """Load existing RSA keys or generate new ones."""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as file:
            private_key = RSA.import_key(file.read())
        with open(PUBLIC_KEY_PATH, "rb") as file:
            public_key = RSA.import_key(file.read())
    else:
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        with open(PRIVATE_KEY_PATH, "wb") as file:
            file.write(private_key.export_key())
        with open(PUBLIC_KEY_PATH, "wb") as file:
            file.write(public_key.export_key())
    
    return public_key.export_key(), private_key.export_key()

public_key, private_key = load_or_generate_keys()

# Encrypt password
def encrypt_password(password, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_password = base64.b64encode(cipher.encrypt(password.encode())).decode()
    return encrypted_password

# Decrypt password
def decrypt_password(encrypted_password, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_password = cipher.decrypt(base64.b64decode(encrypted_password)).decode()
    return decrypted_password

# Encrypt fingerprint vector
def encrypt_vector(vector, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    
    start_time = time.time()  # Start measuring time
    encrypted_vector = [base64.b64encode(cipher.encrypt(v.tobytes())).decode() for v in vector]
    end_time = time.time()  # Stop measuring time

    session['encryption_time'] = round((end_time - start_time) * 1000, 2)  # Convert to milliseconds
    return json.dumps(encrypted_vector)

# Decrypt fingerprint vector
def decrypt_vector(encrypted_vector, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    
    start_time = time.time()  # Start measuring time
    decrypted_vector = [np.frombuffer(cipher.decrypt(base64.b64decode(v)), dtype=np.float32) for v in json.loads(encrypted_vector)]
    end_time = time.time()  # Stop measuring time

    session['decryption_time'] = round((end_time - start_time) * 1000, 2)  # Convert to milliseconds
    return decrypted_vector

# Function to connect to database
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Function to generate a fingerprint vector
def generate_fingerprint_vector():
    return np.random.rand(5).astype(np.float32)  # 5-feature fingerprint vector

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        email = request.form['email']
        mobile = request.form['mobile']
        gender = request.form['gender']
        age = request.form['age']
        password = request.form['password']  # Get password from form
        use_fingerprint = request.form.get("use_fingerprint")  

        fingerprint_data = None  # Default to NULL in the database

        if use_fingerprint == 'on':  # Ensure checkbox is properly checked
            fingerprint_vector = generate_fingerprint_vector()
            encrypted_vector = encrypt_vector(fingerprint_vector, public_key)
            fingerprint_data = encrypted_vector  # Store encrypted fingerprint vector
        
        # Encrypt password before storing
        encrypted_password = encrypt_password(password, public_key)

        db = get_db_connection()
        cursor = db.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (firstname, lastname, username, email, mobile, gender, age, password, fingerprint_data) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (firstname, lastname, username, email, mobile, gender, age, encrypted_password, fingerprint_data))

            db.commit()  
            cursor.close()
            db.close()

            return render_template('fingerprint_scan.html', username=username)
        except mysql.connector.Error as e:
            print(f"❌ Database Error: {e}")  
            db.rollback()  
            return render_template('error1.html', error_message="Database Error, duplicate entry!!")
        finally:
            cursor.close()
            db.close()

    return render_template('register.html')

@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Get password input

        db = get_db_connection()
        cursor = db.cursor()
        try:
            cursor.execute("SELECT password, fingerprint_data FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                stored_encrypted_password = user[0]
                stored_encrypted_vector = user[1]

                # Decrypt stored password
                decrypted_password = decrypt_password(stored_encrypted_password, private_key)

                if decrypted_password != password:
                    return render_template('error.html', error_message="❌ Authentication Failed! Incorrect Password.")

                if stored_encrypted_vector and stored_encrypted_vector != "None":
                    scanned_fingerprint_vector = generate_fingerprint_vector()

                    try:
                        decrypted_vector = decrypt_vector(stored_encrypted_vector, private_key)
                    except ValueError:
                        return render_template('error.html', error_message="Incorrect decryption. Possible key mismatch.")

                    distance = np.linalg.norm(np.array(decrypted_vector) - scanned_fingerprint_vector)
                    threshold = max(1000, np.mean(decrypted_vector) * 100)

                    if distance > threshold:
                        return render_template('error.html', error_message="Fingerprint Mismatch! Try Again.")

                cursor.execute("SELECT firstname, lastname, username, email, mobile, gender, age FROM users WHERE username = %s", (username,))
                user_data = cursor.fetchone()
                if user_data:
                    session['user'] = {'firstname': user_data[0],
                                        'lastname': user_data[1],
                                        'username': user_data[2],
                                        'email': user_data[3],
                                        'mobile': user_data[4],
                                        'gender': user_data[5],
                                        'age': user_data[6]
                                    }
                return render_template('fingerprint_scan1.html', user=session['user'])
            else:
                return render_template('error.html', error_message="❌ User not found! Please register first.")
        except mysql.connector.Error as e:
            return f"Database Error: {e}"
        finally:
            cursor.close()
            db.close()

    return render_template('authenticate.html')
@app.route('/welcome')
def welcome():
    return render_template('welcome.html', user=session['user'])
@app.route('/fingerprint_scan1')
def fingerprint_scan1():
    return render_template('fingerprint_scan1.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('authenticate'))

@app.route('/encryption_time')
def encryption_time():
    encryption_time = session.get('encryption_time', 'N/A')
    decryption_time = session.get('decryption_time', 'N/A')
    return render_template('encryption_time.html', encryption_time=encryption_time, decryption_time=decryption_time)

if __name__ == '__main__':
    app.run(debug=True)
