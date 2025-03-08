from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import mysql.connector
import bcrypt
from flask import Flask, request, jsonify
import mysql.connector
from datetime import datetime



app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your_secret_key"  # Change this to a strong secret key
jwt = JWTManager(app)
CORS(app)  # Allow Flutter to communicate with Flask

# Function to connect to MySQL (Better Connection Pooling)
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Darshika12@", 
        database="attendance_db",
        pool_name="mypool",
        pool_size=5
    )

# Register New User
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email, password = data.get("email"), data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        db.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

# User Login & JWT Token Generation
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email, password = data.get("email"), data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            token = create_access_token(identity=email)
            return jsonify({"token": token})
        
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

# Protected Route (Only for Logged-in Users)
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user}, you are logged in!"})


#


# API to store working hours
@app.route('/save_working_hours', methods=['POST'])
def save_working_hours():
    data = request.json
    user_id = data.get("user_id")
    check_in = data.get("check_in")  # Format: "YYYY-MM-DD HH:MM:SS"
    check_out = data.get("check_out")  # Format: "YYYY-MM-DD HH:MM:SS"

    if not user_id or not check_in or not check_out:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Convert string to datetime
        check_in_time = datetime.strptime(check_in, "%Y-%m-%d %H:%M:%S")
        check_out_time = datetime.strptime(check_out, "%Y-%m-%d %H:%M:%S")

        # Calculate total hours worked
        total_hours = (check_out_time - check_in_time).total_seconds() / 3600  # Convert seconds to hours
        work_date = check_in_time.date()

        db = get_db_connection()
        cursor = db.cursor()

        # Get the number of entries for the user to determine day number
        cursor.execute("SELECT COUNT(*) FROM working_hours WHERE user_id = %s", (user_id,))
        day_number = cursor.fetchone()[0] + 1  # Next available day index

        day_label = f"day{day_number}"

        # Insert working hours for that day
        cursor.execute("""
            INSERT INTO working_hours (user_id, work_date, total_hours, day_label) 
            VALUES (%s, %s, %s, %s)
        """, (user_id, work_date, total_hours, day_label))

        db.commit()
        return jsonify({"message": f"Working hours saved for {day_label}!"}), 201
        returnh
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
