import json
import hashlib
import html
import hmac
import secrets
import bleach
from bson import ObjectId
from datetime import datetime

SECRET_KEY = b"Sonnets_secret_key_here"  # Store securely

def verify_token(auth_token, stored_hash):
    return hmac.compare_digest(
        hashlib.sha256((auth_token + SECRET_KEY).encode()).hexdigest(),
        stored_hash
    )

def create_post(db, request):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        return 403  # Forbidden

    body = request.data.decode()
    try:
        content = json.loads(body)
    except json.JSONDecodeError:
        return 400  # Bad request
    
    if "message" not in content or not isinstance(content["message"], str):
        return 400  # Bad request
    
    user_collection = db["credential"]
    user = user_collection.find_one({})
    
    if not user or not verify_token(auth_token, user["auth_token_hash"]):
        return 403
    
    post_collection = db["posts"]
    sanitized_message = bleach.clean(content["message"])

    post_collection.insert_one({
        "username": user["username"],
        "timestamp": datetime.now(),
        "message": sanitized_message,
        "attachments": [],
        "likes": [],
        "dislikes": [],
        "comments": {}
    })
    
    return 200

def delete_post(db, request, post_id):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        return 403
    
    body = request.data.decode()
    # content = json.loads(body)

    user_collection = db["credential"]
    user = user_collection.find_one({"auth_token_hash": hashlib.sha256(auth_token.encode()).hexdigest()})
    if not user: #add xsrf later
        return 403
    
    post_collection = db["posts"]
    if user["username"] == "Admin":
        result = post_collection.delete_one({"_id": ObjectId(post_id)}) 
    else:
        result = post_collection.delete_one({"username": user["username"], "_id": ObjectId(post_id)})  

    if result.deleted_count > 0:
        return 204
    else:
        return 403

def get_post(db, request):
    post_collection = db["posts"]
    user_collection = db["credential"]
    auth_token = request.cookies.get("auth_token")
    user = user_collection.find_one({"auth_token_hash":hashlib.sha256(auth_token.encode()).hexdigest()})

    posts_list = []
    posts = post_collection.find()


    for post in posts:
        posts_list.append({
            "user": user["username"],
            "id": str(post["_id"]),
            "content": post["message"],
            "author": post["username"],
            "likes": post["likes"], 
            "comments": [{"username": k, "text": v} for k, v in post["comments"].items()],
            "timestamp": post["timestamp"].isoformat()
        })

    return json.dumps(posts_list)

