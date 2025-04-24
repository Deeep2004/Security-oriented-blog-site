from flask import Flask, render_template, make_response, request, redirect, url_for, flash, send_from_directory
from utils.db import connect_db
from utils.login import validate_password
from utils.posts import get_post, create_post, delete_post
import hashlib
import secrets
import bcrypt
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import redis

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

db = connect_db()
if db is not None:
    print('Database connected successfully')
else:
    print('Database not connected')
credential_collection = db["credential"]

rate_limiter = redis.Redis(host='redis', port=6379, db=1, decode_responses=True)

RATE_LIMIT = 100  # Max requests
TIME_WINDOW = 60  # Time window in seconds
# request_counts = {}  # Stores request timestamps


ENDPOINT_LIMITS = {
    "/posts": 60,
    "/login": 10,
    "/comments": 20,
} 

def rate_limit(ip, endpoint):
    """Rate limiter using Redis sorted sets with per-endpoint limits"""
    key = f"rate_limit:{endpoint}:{ip}"
    now = time.time()
    
    limit = ENDPOINT_LIMITS.get(endpoint, RATE_LIMIT)
    rate_limiter.zremrangebyscore(key, 0, now - TIME_WINDOW)
    current_count = rate_limiter.zcard(key)

    if current_count >= limit:
        return False  

    rate_limiter.zadd(key, {str(now): now})
    rate_limiter.expire(key, TIME_WINDOW + 5)

    return True 


# def rate_limit2(ip):
#     current_time = time.time()
#     if ip not in request_counts:
#         request_counts[ip] = []
    
#     # Remove expired timestamps
#     request_counts[ip] = [t for t in request_counts[ip] if current_time - t < TIME_WINDOW]

#     if len(request_counts[ip]) < RATE_LIMIT:
#         request_counts[ip].append(current_time)
#         return True
#     else:
#         return False
    

@app.route('/css/<path:filename>', methods=['GET'])
def serve_css(filename):
    response = make_response(send_from_directory('static/css', filename))
    response.mimetype = "text/css"
    return response

@app.route('/js/<path:filename>', methods=['GET'])
def serve_js(filename):
    response = make_response(send_from_directory('static', filename))
    response.mimetype = "text/javascript"
    return response

@app.route('/images/<path:filename>', methods=['GET'])
def serve_image(filename):
    response = make_response(send_from_directory('static/images', filename))
    return response
#functions to serve static files


@app.after_request
def add_nosniff_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
#function to add nosniff to every response

@app.route('/login', methods=['GET','POST'])
def login():
    ip = request.remote_addr  
    if not rate_limit(ip, "login"):  
        return make_response("Too many requests, please try again later.", 429)
    
    # ip = request.remote_addr
    # if not rate_limit2(ip):
    #     return make_response("Too many requests, please try again later.", 429)

    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = credential_collection.find_one({"username": username})
        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            flash("Invalid username/password", "error")
            response = make_response(redirect(url_for('login')))
            response.mimetype = "text/html"
            return response

        response = make_response(redirect('/'))
        auth_token = secrets.token_hex(16)
        hash_auth_token = hashlib.sha256(auth_token.encode('utf-8')).hexdigest()
        credential_collection.update_one(
            {"username": username},
            {"$set": {"auth_token_hash": hash_auth_token}}
        )
        response.set_cookie('auth_token', auth_token, httponly=True, max_age=3600)
        response.mimetype = "text/html"
        return response
    
    if request.method == 'GET':
        auth_token = request.cookies.get('auth_token')
        if auth_token:
            user = credential_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
            if user:
                response = make_response(redirect('/'))
                response.mimetype = "text/html"
                return response
            
        response = make_response(render_template('login.html'))
        response.set_cookie('auth_token', '', expires=0)
        response.mimetype = "text/html"
        return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = request.remote_addr
    if not rate_limit(ip, "register"):
        return make_response("Too many requests, please try again later.", 429)
    
    # ip = request.remote_addr
    # if not rate_limit2(ip):
    #     return make_response("Too many requests, please try again later.", 429)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match", "error")
            response = make_response(render_template('register.html'))
            response.mimetype = "text/html"
            return response

        # Check if password meets strength requirements
        if not validate_password(password):
            flash("Password does not meet the requirements:<br>- 8+ characters<br>- 1 lowercase letter<br>- 1 uppercase letter<br>- 1 special character: !,@,#,$,%,^,&,(,),-,_,=", "error")
            response = make_response(render_template('register.html'))
            response.mimetype = "text/html"
            return response

        # Check if the username is already taken
        if credential_collection.find_one({"username": username}):
            flash("Username already taken", "error")
            response = make_response(render_template('register.html'))
            response.mimetype = "text/html"
            return response
        
        if credential_collection.find_one({"email": email}):
            flash("email already used by other account, please try another email!", "error")
            response = make_response(render_template('register.html'))
            response.mimetype = "text/html"
            return response    

        # Hash the password with bcrypt and insert into database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        credential_collection.insert_one({
            "username": username,
            "email": email,
            "password_hash": hashed_password
        })

        body = "Welcome to our website!\n You have register for our CSE 418 website and we are excited to have you!"
        subject = "Account registration"
        send_email(email, subject, body) #send email when register
        response = make_response(redirect(url_for('login')))
        response.mimetype = "text/html"
        return response

    # GET request
    response = make_response(render_template('register.html'))
    response.mimetype = "text/html"
    return response


@app.route('/logout', methods=['GET'])
def logout():
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        user = credential_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
        if user:
            credential_collection.update_one({"_id": user["_id"]}, {"$set": {"auth_token_hash": None}})

    response = make_response(redirect(url_for('login')))
    response.set_cookie('auth_token', '', expires=0)
    return response


@app.route('/', methods=['GET'])
def home():
    if "auth_token" not in request.cookies:
        response = make_response(redirect(url_for("login"), 302))
        response.mimetype = "text/html"
        return response
    #if not logged in redirect back to login
    
    auth_token = request.cookies.get("auth_token")
    user = credential_collection.find_one({"auth_token_hash":hashlib.sha256(auth_token.encode()).hexdigest()})
    if not user:
        response = make_response(redirect(url_for("login"), 302))
        response.set_cookie('auth_token', '', expires=0)
        response.mimetype = "text/html"
        return response
    #if using invalid auth_token, redirect back to login

    username = user['username']
    response = make_response(render_template('home_page.html', username=username))
    response.mimetype = "text/html"
    return response


@app.route('/posts', methods=['GET','POST'])
def posts():
    ip = request.remote_addr
    if not rate_limit(ip, "posts"):
        return make_response("Too many requests, please try again later.", 429)
    
    # ip = request.remote_addr
    # if not rate_limit2(ip):
    #     return make_response("Too many requests, please try again later.", 429)

    
    if request.method == 'GET':
        posts = get_post(db, request)
        response = make_response()
        response.set_data(posts)
        response.mimetype = "application/json"
        return response
    if request.method == 'POST':
        code = create_post(db, request)
        if code == 403:
            response = make_response("Permission Denied", 403)
            response.mimetype = "text/plain"
            return response  

        elif code == 200:
            response = make_response('', 200) 
            response.mimetype = "text/plain"
            return response  
        

@app.route('/posts/<string:post_id>', methods=['DELETE'])
def delete_posts(post_id):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        print(1)
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response

    user = credential_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
    if not user:
        print(2)
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response

    print(user["username"])

    post = db["posts"].find_one({"_id": ObjectId(post_id)})
    if user['username'] != "Admin" and (not post or post['username'] != user['username']):
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response
    

    code = delete_post(db, request, post_id)

    if code == 403:
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response  

    elif code == 204:
        response = make_response("No Content", 204)
        response.mimetype = "text/plain"
        return response  

    
@app.route('/like/<string:post_id>', methods=['POST'])
def like_post(post_id):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response  
    
    user = credential_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
    if not user:
        response = make_response("Permission Denied", 403)
        response.mimetype = "text/plain"
        return response  
    
    post_collection = db["posts"]
    post_collection.update_one(
        {"_id": ObjectId(post_id)},
        {"$addToSet": {"likes": user["username"]}}
    )

    response = make_response("OK", 200)
    response.mimetype = "text/plain"
    return response



@app.route('/delete_account/', methods=['POST', 'DELETE'], strict_slashes=False)
def delete_account():
    auth_token = request.cookies.get("auth_token")
    
    if not auth_token:
        flash("Authentication token missing.", "error")
        return redirect(url_for("login"))

    user = credential_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
    if not user:
        flash("Invalid or expired token.", "error")
        return redirect(url_for("login"))

    # Step 1: Delete user's posts
    post_collection = db["posts"]
    post_collection.delete_many({"username": user["username"]})

    # Step 2: Delete user's credentials
    credential_collection.delete_one({"_id": user["_id"]})
    subject = "Account Deletion "
    body = "Your account has been successfully deleted from our system. Thank you for using our website."
    send_email(user['email'], subject, body)

    # Step 3: Clear the auth_token cookie and redirect
    response = make_response(redirect(url_for("login")))
    response.set_cookie('auth_token', '', expires=0)
    response.mimetype = "text/html"
    return response

def send_email(receiver_email, subject, body):
    sender_email = "ub418sec@gmail.com"
    password = "mlbs vebb iaxp udtb" 

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()
    print("Message sent")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)