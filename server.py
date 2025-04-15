import os
from dotenv import load_dotenv
load_dotenv()
import smtplib
from email.mime.text import MIMEText
import stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
import psycopg2
import bcrypt
import time
from flask import Flask, request, jsonify, session, redirect, send_from_directory, render_template
from flask_cors import CORS
from flask_session import Session
from psycopg2.extras import RealDictCursor
import openai
from urllib.parse import urlparse

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
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# OpenAI Assistant ID (Replace with your actual Assistant ID)
ASSISTANT_ID = "asst_BVHJcqvmsENpjqhBlHI07sre"

def get_db_connection():
    """Connects to PostgreSQL, using SSL only if not localhost."""
    try:
        result = urlparse(os.environ.get("DATABASE_URL"))
        ssl_required = result.hostname != "localhost"

        conn_args = {
            "database": result.path[1:],
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port,
        }

        if ssl_required:
            conn_args["sslmode"] = "require"

        return psycopg2.connect(**conn_args)
    except Exception as e:
        print(f"Database connection error: {e}")
        return None  # Return None if the connection fails

def send_reset_email(recipient_email, token):
    reset_link = f"{request.host_url}reset-password?token={token}"
    subject = "HOPE.AI Password Reset"
    body = f"""Hello,

We received a request to reset your HOPE.AI password.

To reset your password, click the link below:
{reset_link}

If you did not request this, please send notify support@naveonguides.com.

– The HOPE.AI Team
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "paul@naveonguides.com"
    msg["To"] = recipient_email

    try:
        print("[DEBUG] Preparing to send email...")
        print(f"[DEBUG] SMTP Server: {SMTP_SERVER}")
        print(f"[DEBUG] SMTP Port: {SMTP_PORT}")
        print(f"[DEBUG] SMTP Username: {SMTP_EMAIL}")
        print(f"[DEBUG] Recipient: {recipient_email}")

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.set_debuglevel(1)
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[INFO] Sent password reset email to {recipient_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send reset email: {e}")


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
                        role VARCHAR(10) DEFAULT 'user',
                        query_count INTEGER DEFAULT 0,
                        license_key VARCHAR(100)
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

@app.route("/admin-licenses.html", methods=["GET"])
def serve_admin_licenses_page():
    """Serve the license dashboard HTML."""
    if session.get("role") != "admin":
        return redirect("/login")
    return send_from_directory("static", "admin-licenses.html")

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
    email = data.get("email").strip().lower()
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, password, role, query_count, license_key FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

                if not user or not bcrypt.checkpw(password.encode("utf-8"), user[1].encode("utf-8")):
                    return jsonify({"error": "Invalid credentials"}), 401

                session["user_id"] = user[0]
                session["email"] = email
                session["role"] = user[2]
                if user[4] is None:
                    domain = email.split("@")[-1]
                    cur.execute("SELECT license_key FROM licenses WHERE domain = %s", (domain,))
                    license_match = cur.fetchone()
                    if license_match:
                        license_key = license_match[0]
                        cur.execute("UPDATE users SET license_key = %s WHERE id = %s", (license_key, user[0]))
                        conn.commit()

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

@app.route("/admin/assign-license", methods=["POST"])
def assign_license():
    """Admin generates and assigns a license key to a user."""
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    email = data.get("email")
    license_key = data.get("licenseKey")

    if not email or not license_key:
        return jsonify({"error": "Email and license key are required"}), 400

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET license_key = %s WHERE email = %s", (license_key, email))
                if cur.rowcount == 0:
                    return jsonify({"error": "User not found"}), 404
                conn.commit()
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({"success": True, "licenseKey": license_key})

@app.route("/admin/licenses", methods=["GET"])
def get_licenses_dashboard():
    """Return license data for admin dashboard."""
    if session.get("role") != "admin":
        return redirect("/login")

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(''' 
                    SELECT 
                        l.domain,
                        l.tier,
                        l.license_key,
                        COUNT(u.id) AS user_count
                    FROM licenses l
                    LEFT JOIN users u ON l.domain = SPLIT_PART(u.email, '@', 2)
                    GROUP BY l.domain, l.tier, l.license_key
                    ORDER BY l.domain;
                ''')
                licenses = cur.fetchall()
    except Exception as e:
        print(f"License dashboard error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({"licenses": licenses})

@app.route("/purchase-license", methods=["GET"])
def serve_purchase_license():
    """Serve the purchase license form."""
    return send_from_directory("static", "purchase-license.html")

@app.route("/purchase-license", methods=["POST"])
def purchase_license():
    """Simulate license generation and store by domain."""
    data = request.get_json()
    email = data.get("email")
    tier = data.get("tier")

    if not email or not tier:
        return jsonify({"error": "Email and license tier are required."}), 400

    domain = email.split("@")[-1]
    license_key = f"HOPE-{domain.upper()}-{str(int(time.time()))}"
    tier_prices = {"1": 500, "3-5": 900, "5-10": 3500, "10+": 5000}
    price = tier_prices.get(tier, 0)

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id SERIAL PRIMARY KEY,
                        domain TEXT UNIQUE NOT NULL,
                        license_key TEXT NOT NULL,
                        tier TEXT,
                        price INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cur.execute('''
                    INSERT INTO licenses (domain, license_key, tier, price)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (domain) DO UPDATE
                    SET license_key = EXCLUDED.license_key,
                        tier = EXCLUDED.tier,
                        price = EXCLUDED.price,
                        created_at = CURRENT_TIMESTAMP;
                ''', (domain, license_key, tier, price))
                conn.commit()
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({"success": True, "licenseKey": license_key, "price": price})

@app.route("/register", methods=["POST"])
def register_user():
    """Handles user registration and logs them in."""
    data = request.get_json()
    email = data.get("email").strip().lower()
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                # Check if user already exists
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({"error": "Email is already registered."}), 409

                # Check for license match by domain
                domain = email.split("@")[-1]
                cur.execute("SELECT license_key FROM licenses WHERE domain = %s", (domain,))
                license_match = cur.fetchone()
                assigned_license = license_match[0] if license_match else None

                # Insert user with assigned license if available
                cur.execute("""
                    INSERT INTO users (email, password, role, query_count, license_key)
                    VALUES (%s, %s, 'user', 0, %s)
                    RETURNING id;
                """, (email, hashed_password, assigned_license))
                user_id = cur.fetchone()[0]
                conn.commit()

                # Log them in
                session["user_id"] = user_id
                session["email"] = email
                session["role"] = "user"
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({"success": True})

@app.route("/register", methods=["GET"])
def serve_register():
    """Serve the user registration page."""
    return send_from_directory("static", "register.html")

# Restrict access unless logged in
@app.before_request
def require_login():
    allowed_routes = [
        "/login",
        "/logout",
        "/admin",
        "/register",
        "/purchase-license",
        "/create-checkout-session",
        "/purchase-license-success",
        "/forgot-password",
        "/reset-password",
    ]
    if (request.path not in allowed_routes and
        not request.path.startswith("/static/") and
        "user_id" not in session):
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

        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT query_count, license_key FROM users WHERE id = %s", (user_id,))
                user_info = cur.fetchone()
                query_count = user_info[0]
                license_key = user_info[1]

                if license_key is None and query_count >= 3:
                    return jsonify({"error": "Query limit reached. Upgrade your plan to continue."}), 403

                # Increment query count for non-licensed users
                if license_key is None:
                    cur.execute("UPDATE users SET query_count = query_count + 1 WHERE id = %s", (user_id,))
                    conn.commit()

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
        import json
        raw_text = messages.data[0].content[0].text.value
        try:
            parsed = json.loads(raw_text)
            answer = parsed.get("answer", "")
            file_map = {
                "HOPE Guidance Manual v1.00": "hope-guidance-manual_v1.00.pdf",
                "HOPE Guidance Manual v1.02": "hope-guidance-manual_v1.00.pdf",
                "HQRP Development Report": "hqrp_hospice_outcomes_and_patient_evaluation_hope_development_and_testing_report.pdf",
                "HOPE QM User Manual": "hqrp_qm_user_manual_chapter-hope_measures_508c.pdf",
                "HOPE Update Visit Form v1.00": "hope-v1.00_hope-update-visit_508c.pdf",
                "HOPE Discharge Form v1.00": "hope-v1.00_discharge_508c.pdf",
                "HOPE Admission Form v1.00": "hope-v1.00_admission_508c.pdf",
                "HOPE All Items v1.00": "hope-v1.00_all-item_508c.pdf"
            }
            citations = []
            for cite in parsed.get("citations", []):
                doc_label = cite.get("document")
                page_number = cite.get("page_number")
                file_name = file_map.get(doc_label)
                if file_name:
                    citations.append({
                        "file_name": file_name,
                        "page_number": page_number
                    })
        except json.JSONDecodeError:
            answer = raw_text
            citations = []
 
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

        return jsonify({
            "answer": answer,
            "citations": citations
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    data = request.get_json()
    email = data.get("email")
    tier = data.get("tier")
    promo_code = data.get("promo")

    if not email or not tier:
        return jsonify({"error": "Email and tier are required"}), 400

    # Replace with your real Stripe Price IDs
    tier_prices = {
        "1": "price_1RDZ4ZHhUWgABYbCESuzfSzw",     # 1–2 Locations – $500
        "3-5": "price_1RDZ4ZHhUWgABYbC8rdJzr0z",    # 3–5 Locations – $900
        "6-10": "price_1RDZ4ZHhUWgABYbCNlqrXK4p",   # 6–10 Locations – $3500
        "11+": "price_1RDZ4ZHhUWgABYbCsA3ATVOB"     # Enterprise (11+) – $5000
    }

    price_id = tier_prices.get(tier)
    if not price_id:
        return jsonify({"error": "Invalid license tier"}), 400

    # Generate and store license immediately
    domain = email.split("@")[-1]
    license_key = f"HOPE-{domain.upper()}-{str(int(time.time()))}"

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(''' 
                    INSERT INTO licenses (domain, license_key, tier, price)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (domain) DO UPDATE
                    SET license_key = EXCLUDED.license_key,
                        tier = EXCLUDED.tier,
                        price = EXCLUDED.price,
                        created_at = CURRENT_TIMESTAMP;
                ''', (domain, license_key, tier, 0))
                conn.commit()
    except Exception as e:
        print(f"Database error while creating license: {e}")

    try:
        session_args = {
            "payment_method_types": ["card"],
            "line_items": [{
                "price": price_id,
                "quantity": 1
            }],
            "mode": "payment",
            "success_url": f"{request.host_url}purchase-license-success?email={email}",
            "cancel_url": f"{request.host_url}purchase-license?email={email}"
        }
        if promo_code:
            try:
                promo = stripe.PromotionCode.list(code=promo_code, active=True).data
                if promo:
                    session_args["discounts"] = [{"promotion_code": promo[0].id}]
                else:
                    return jsonify({"error": "Invalid or inactive promo code."}), 400
            except Exception as e:
                print(f"Stripe promo lookup error: {e}")
                return jsonify({"error": "Failed to validate promo code."}), 500

        session = stripe.checkout.Session.create(**session_args)
        return jsonify({"url": session.url})
    except Exception as e:
        print(f"Stripe error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/purchase-license-success", methods=["GET"])
def purchase_license_success():
    """Confirmation page shown after successful Stripe payment."""
    email = request.args.get("email")
    domain = email.split("@")[-1]

    license_key = "Unavailable"
    tier = "Unavailable"

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT license_key, tier FROM licenses WHERE domain = %s", (domain,))
                result = cur.fetchone()
                if result:
                    license_key, tier = result
    except Exception as e:
        print(f"License confirmation error: {e}")
    finally:
        if conn:
            conn.close()

    return f"""
<html>
<head>
  <title>Purchase Successful</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body style="font-family: Arial; padding: 20px;">
  <div class="container">
    <div class="text-center mb-3">
      <img src="/static/images/naveon-logo.png" alt="Naveon Logo" style="max-height: 60px;">
    </div>
    <h2 class="text-success mt-4">✅ Thank You for Your Purchase!</h2>
    <p>The HOPE.AI license for <strong>{email}</strong> has been activated.</p>
    <p><strong>License Tier:</strong> {tier}</p>
    <p><strong>License Key:</strong> <code>{license_key}</code></p>
    <button class="btn btn-outline-secondary mt-3" onclick="downloadReceipt()">🧾 Download Receipt (TXT)</button>
    <p class="mt-3">You may now close this window or click "Back to Home" to access HOPE.AI.  Anyone in your email domain now has access to HOPE.AI after signing up with their organization email.</p>
    <a href="/" class="d-block mt-3">Back to Home</a>
  </div>

  <script>
    function downloadReceipt() {{
      const receipt = `
        HOPE.AI License Receipt

        Email: {email}
        Domain: {domain}
        License Tier: {tier}
        License Key: {license_key}
        Date: ` + new Date().toLocaleDateString() + `
      `;
      const blob = new Blob([receipt], {{ type: "text/plain" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "hopeai_license_receipt.txt";
      a.click();
      URL.revokeObjectURL(url);
    }}
  </script>
</body>
</html>
"""

@app.route("/files/view/<filename>")
def view_file(filename):
    """Serves PDF files from the static/files directory."""
    return send_from_directory("static/files", filename)

@app.route("/user-guide")
def serve_user_guide():
    return send_from_directory("static", "user-guide.html")

@app.route("/forgot-password", methods=["GET"])
def forgot_password():
    print("[DEBUG] Forgot password route hit")
    return render_template("forgot-password.html")

@app.route("/forgot-password", methods=["POST"])
def handle_forgot_password():
    """Handle the password reset request and prepare to email a reset link."""
    email = request.form.get("email").strip().lower()
    if not email:
        return "Email is required.", 400

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                if not user:
                    return "If the email exists, a reset link will be sent.", 200

                import uuid
                reset_token = str(uuid.uuid4())

                # Placeholder: just log the token for now
                print(f"[INFO] Generated reset token for {email}: {reset_token}")
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id SERIAL PRIMARY KEY,
                        email TEXT NOT NULL,
                        token TEXT NOT NULL,
                        expires_at TIMESTAMP NOT NULL
                    );
                ''')
                expires_in_seconds = 900  # 15 minutes
                cur.execute('''
                    INSERT INTO password_reset_tokens (email, token, expires_at)
                    VALUES (%s, %s, NOW() + INTERVAL '1 second' * %s)
                ''', (email, reset_token, expires_in_seconds))
                send_reset_email(email, reset_token)

    except Exception as e:
        print(f"[ERROR] Password reset error for {email}: {str(e)}")
        return "Something went wrong.", 500

    return "If the email exists, a reset link will be sent.", 200

@app.route("/reset-password", methods=["GET"])
def serve_reset_password_page():
    token = request.args.get("token")
    if not token:
        return "Invalid reset link.", 400
    return render_template("reset-password.html", token=token)

@app.route("/reset-password", methods=["POST"])
def handle_reset_password():
    token = request.form.get("token")
    password = request.form.get("password")
    confirm = request.form.get("confirm")

    if not token or not password or not confirm:
        return "All fields are required.", 400
    if password != confirm:
        return "Passwords do not match.", 400

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(''' 
                    SELECT email FROM password_reset_tokens 
                    WHERE token = %s AND expires_at > NOW()
                ''', (token,))
                result = cur.fetchone()
                if not result:
                    return "Reset link is invalid or has expired.", 400

                email = result[0]
                hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

                # Update password
                cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))

                # Invalidate token
                cur.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
                conn.commit()
    except Exception as e:
        print(f"[ERROR] Password reset failed: {e}")
        return "Server error. Please try again later.", 500

    return redirect("/login")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
