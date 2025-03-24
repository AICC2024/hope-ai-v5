import os
import psycopg2
import bcrypt
import time
from flask import Flask, request, jsonify, session, redirect, send_from_directory
from flask_cors import CORS
from flask_session import Session
from psycopg2.extras import RealDictCursor
import openai

# Flask app setup
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

app.secret_key = "your-secret-key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# PostgreSQL Configuration
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_DATABASE = os.getenv("PG_DATABASE", "hopeai_db")
PG_USER = os.getenv("PG_USER", "hopeai_user")
PG_PASSWORD = os.getenv("PG_PASSWORD", "Admin2025")

# OpenAI API Configuration
openai.api_key = os.getenv("OPENAI_API_KEY")

# OpenAI Assistant ID (Replace with your actual Assistant ID)
ASSISTANT_ID = "asst_BVHJcqvmsENpjqhBlHI07sre"

def get_db_connection():
    """Establish PostgreSQL connection."""
    try:
        return psycopg2.connect(
            host=PG_HOST,
            database=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
    except Exception as e:
        print(f"Database connection error: {e}")
        return None  # Return None if the connection fails


# Ensure users table exists
def init_db():
    """Creates the users and chat tables in PostgreSQL if they don't exist."""
    conn = get_db_connection()
    if conn is None:
        print("Database initialization skipped due to connection failure.")
        return

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        role VARCHAR(10) DEFAULT 'user'
                    );
                ''')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS chat (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        question TEXT NOT NULL,
                        answer TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS activity_log (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        action TEXT NOT NULL,
                        details TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                conn.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        if conn:
            conn.close()

init_db()

@app.route('/history', methods=['GET'])
def get_chat_history():
    """Retrieves chat history for the logged-in user from PostgreSQL and returns it as JSON."""
    user_id = session.get("user_id")  # Get logged-in user ID

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401  # User must be logged in

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Retrieve chat history **only for the logged-in user**
                cur.execute(
                    "SELECT question, answer, timestamp FROM chat WHERE user_id = %s ORDER BY timestamp DESC",
                    (user_id,)
                )
                history = cur.fetchall()
    except Exception as e:
        print("Database error:", str(e))
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({"history": history})
@app.route("/history-page", methods=["GET"])
def serve_history_page():
    """Serve the chat history page."""
    return send_from_directory("static", "history.html")
@app.route("/login", methods=["GET"])
def serve_login():
    """Serve the login page."""
    return send_from_directory("static", "login.html")
# Serve Admin Page
@app.route("/admin")
def serve_admin():
    """Serve the admin panel for adding users."""
    if session.get("role") != "admin":
        return redirect("/login")  # Only admins can access
    return send_from_directory("static", "admin.html")

# API to Add Users (Admin Only)
@app.route("/admin/add-user", methods=["POST"])
def add_user():
    """Allows the admin to create new users."""
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
                conn.commit()
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400
    finally:
        if conn:
            conn.close()

    return jsonify({"success": True, "message": "User added successfully"})

# API to Log In a User
@app.route("/login", methods=["POST"])
def login_user():
    """Handles user login using email & password and logs the activity."""
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, password, role FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

                if not user or not bcrypt.checkpw(password.encode("utf-8"), user[1].encode("utf-8")):
                    return jsonify({"error": "Invalid credentials"}), 401

                session["user_id"] = user[0]
                session["email"] = email
                session["role"] = user[2]

                # Log the login event
                cur.execute("INSERT INTO activity_log (user_id, action) VALUES (%s, %s)", (user[0], "login"))
                conn.commit()

                return jsonify({"success": True, "message": "Login successful"})
    finally:
        if conn:
            conn.close()

# API to Log Out a User
@app.route("/logout", methods=["POST"])
def logout_user():
    """Logs out the user and records the event in activity_log."""
    user_id = session.get("user_id")
    
    if user_id:
        try:
            conn = get_db_connection()
            with conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO activity_log (user_id, action) VALUES (%s, %s)", (user_id, "logout"))
                    conn.commit()
        finally:
            if conn:
                conn.close()
    
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})

@app.route("/is_logged_in", methods=["GET"])
def is_logged_in():
    """Returns user login status and role."""
    if "user_id" in session:
        return jsonify({
            "logged_in": True,
            "email": session["email"],
            "role": session["role"]
        })
    return jsonify({"logged_in": False})

# Restrict access unless logged in
@app.before_request
def require_login():
    allowed_routes = ["/login", "/logout", "/admin"]
    if request.path not in allowed_routes and "user_id" not in session:
        return redirect("/login")

# Serve the frontend
@app.route('/')
def serve_frontend():
    return send_from_directory("static", "index.html")

# API Endpoint to Process User Questions with OpenAI
@app.route('/ask', methods=['POST'])
def ask_hope_ai():
    """Processes user questions, sends them to OpenAI, and logs the conversation."""
    try:
        data = request.json
        user_query = data.get("question")
        user_id = session.get("user_id")  # Get logged-in user ID

        if not user_query:
            return jsonify({"error": "Question is required"}), 400

        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401  # User must be logged in

        print("Creating thread for conversation tracking...")

        # Create a new thread for each conversation
        thread = openai.beta.threads.create()

        # Send the user's question to the Assistant
        message = openai.beta.threads.messages.create(
            thread_id=thread.id,
            role="user",
            content=user_query
        )

        print("Starting assistant run...")

        # Start an assistant run
        run = openai.beta.threads.runs.create(
            thread_id=thread.id,
            assistant_id=ASSISTANT_ID
        )

        # Wait for completion
        while run.status not in ["completed", "failed"]:
            time.sleep(2)
            run = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)

        if run.status == "failed":
            print("Assistant failed to generate a response.")
            return jsonify({"error": "Assistant failed to generate a response."})

        print("Retrieving assistant's response...")

        # Retrieve the assistant's response
        messages = openai.beta.threads.messages.list(thread_id=thread.id)
        answer = messages.data[0].content[0].text.value  # Extract the response

        # Save conversation to PostgreSQL
        try:
            conn = get_db_connection()
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO chat (user_id, question, answer) VALUES (%s, %s, %s)",
                        (user_id, user_query, answer)
                    )
                    conn.commit()

                    # Log the chatbot interaction
                    cur.execute(
                        "INSERT INTO activity_log (user_id, action, details) VALUES (%s, %s, %s)",
                        (user_id, "chat", f"Q: {user_query} | A: {answer}")
                    )
                    conn.commit()
        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        finally:
            if conn:
                conn.close()

        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
