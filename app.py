from flask import Flask, request, jsonify
from flask_cors import CORS
from groq import Groq
from dotenv import load_dotenv
import os
import psycopg2
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn



app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")

CORS(app, 
     resources={r"/*": {
         "origins": [FRONTEND_ORIGIN,"http://127.0.0.1:5500"],
         "methods": ["GET", "POST", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],  
         "supports_credentials": True
     }})


@app.route('/register',methods=['POST'])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s) RETURNING id", (email, hashed_password))
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.check_password_hash(user[1], password):
        access_token = create_access_token(identity=str(user[0]))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user_id = int(get_jwt_identity())
    return jsonify({"message": "Access granted", "user_id": user_id}), 200


@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    try:
        user_id = int(get_jwt_identity())

        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415

        user_message = request.json.get("message")
        
        # Get recent conversation history
        conn = get_db_connection()
        cur = conn.cursor()
        # Limit to last N messages to stay within context window
        cur.execute(
            """
            SELECT message, response
            FROM chats
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 10
            """,
            (user_id,)
        )
        recent_chats = cur.fetchall()
        cur.close()
        
        # Build conversation history in reverse chronological order
        messages = []
        # Add previous messages in chronological order
        for msg, resp in reversed(recent_chats):
            messages.append({"role": "user", "content": msg})
            messages.append({"role": "assistant", "content": resp})
        
        # Add the current message
        messages.append({"role": "user", "content": user_message})

        try:
            client = Groq(api_key=os.getenv("GROQ_API_KEY"))
            completion = client.chat.completions.create(
                messages=messages,
                model="llama-3.3-70b-versatile",
            )
            ai_response = completion.choices[0].message.content

            # Save to database (same as before)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO chats (user_id, message, response) VALUES (%s, %s, %s) RETURNING id",
                (user_id, user_message, ai_response)
            )
            chat_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()

            return jsonify({
                "response": ai_response,
                "chat_id": chat_id
            })

        except Exception as e:
            return jsonify({"error": f"Failed to process message: {str(e)}"}), 503

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    

@app.route('/my-chats', methods=['GET'])
@jwt_required()
def get_user_chats():
    try:
        user_id = int(get_jwt_identity())
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        if page < 1:
            return jsonify({"error": "Page number must be positive"}), 400
        if per_page < 1 or per_page > 50:
            return jsonify({"error": "Messages per page must be between 1 and 50"}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT COUNT(*) 
            FROM chats 
            WHERE user_id = %s
        """, (user_id,))
        total_messages = cur.fetchone()[0]
        
        total_pages = (total_messages + per_page - 1) // per_page
        
        cur.execute("""
            SELECT id, message, response, timestamp 
            FROM chats 
            WHERE user_id = %s 
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """, (user_id, per_page, (page - 1) * per_page))
        
        chats = cur.fetchall()
        
        chat_history = [{
            "id": chat[0],
            "message": chat[1],
            "response": chat[2],
            "timestamp": chat[3].isoformat()
        } for chat in chats]
        
        cur.close()
        conn.close()
        
        return jsonify({
            "history": chat_history,
            "pagination": {
                "current_page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "total_messages": total_messages,
                "has_next": page < total_pages,
                "has_previous": page > 1
            }
        })

    except Exception as e:
        return jsonify({"error": "Failed to retrieve chat history"}), 500



@app.route('/chat-history', methods=['GET'])
@jwt_required()
def get_chat_history():
    try:
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, message, response, timestamp 
            FROM chats 
            WHERE user_id = %s 
            ORDER BY timestamp DESC
            """, 
            (user_id,)
        )
        chats = cur.fetchall()
        cur.close()
        conn.close()

        chat_history = [{
            "id": chat[0],
            "message": chat[1],
            "response": chat[2],
            "timestamp": chat[3].isoformat()
        } for chat in chats]

        return jsonify({"history": chat_history})

    except Exception as e:
        return jsonify({"error": "Failed to retrieve chat history"}), 500


if __name__ == "__main__":
    app.run(debug=True)