from pymongo import MongoClient

def connect_db():
    try:
        mongo_client = MongoClient("mongodb://mongo:27017/", serverSelectionTimeoutMS=5000)
        
        db = mongo_client["cse312"]
        mongo_client.admin.command('ping')
        print("Database connected successfully")
        return db
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None
