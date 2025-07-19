from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2 import Error
import bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'sslmode': 'verify-full',
    'sslrootcert': os.getenv('SSL_ROOT_CERT')
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not all(k in data for k in ['username', 'email', 'password']):
        return jsonify({'error': 'Username, email, and password required'}), 400

    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400

        cursor.execute("""
            INSERT INTO users (username, email, password, plain_password)
            VALUES (%s, %s, %s, %s)
            RETURNING id, username, email, role
        """, (data['username'], data['email'], hashed_pw.decode('utf-8'), data['password']))

        new_user = cursor.fetchone()
        conn.commit()

        return jsonify({
            'id': new_user[0],
            'username': new_user[1],
            'email': new_user[2],
            'role': new_user[3],
            'enrolledCourses': []
        }), 201
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'error': 'Email and password required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, username, email, password, role FROM users WHERE email = %s", (data['email'],))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        stored_hash = user[3].encode('utf-8')
        if not bcrypt.checkpw(data['password'].encode('utf-8'), stored_hash):
            return jsonify({'error': 'Invalid credentials'}), 401

        cursor.execute("SELECT course_id FROM enrollments WHERE user_id = %s", (user[0],))
        enrolled_courses = [row[0] for row in cursor.fetchall()]

        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[4],
            'enrolledCourses': enrolled_courses
        }), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
