from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import os
from bson import ObjectId
from datetime import datetime
import pytz

load_dotenv(find_dotenv())

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["yt_chatbot"]



def get_all_users():
    users = db.users.find({})
    users = list(users)
    for user in users:
        user['_id'] = str(user['_id'])
    return users


def get_user(user_id):
    user = db.users.find_one({'_id': ObjectId(user_id)})
    if user:
        user['_id'] = str(user['_id'])
        return user
    else:
        return False
    


def login_user(email, password):
    user = db.users.find_one({'email': email})
    if user:
        if user['password'] == password:
            user['_id'] = str(user['_id'])
            return [user.get('_id'),user.get('role')]
        else:
            return False
    else:
        return False


def register_user(clerk_id, email, first_name, last_name, profile_image_url):
    print(f"Inserting new user: {clerk_id}")  # Debug statement
    # Insert new user
    result = db.users.insert_one({
        'clerk_id': clerk_id,
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'profile_image_url': profile_image_url,
        'role': 'user'  # Default role, adjust as necessary
    })
    print(f"New user inserted with ID: {result.inserted_id}")  # Debug statement
    return str(result.inserted_id)


def update_user(user_id, user_data):
    """Update a user's information based on data from Clerk."""
    result = db.users.update_one(
        {'clerk_id': user_id},  # Assuming you store Clerk's user ID in a 'clerk_id' field
        {'$set': user_data}  # Update fields provided in user_data
    )
    return result.modified_count > 0  # Return True if the update was successful



def delete_user(user_id):
    """Delete a user based on Clerk's user ID."""
    result = db.users.delete_one({'clerk_id': user_id})
    return True  # Return True if a user was deleted



# save transcripts of a youtube channel according to user id and channel url
def save_transcripts(user_id,transcript,channel_id):
    try:
        ans=db.transcripts.insert_one({'user_id': user_id, 'transcript': transcript, 'channel_id': channel_id})
        # retun transcript 
        return ans.inserted_id
    except Exception as e:
        print(f"Error saving transcript: {e}")
        return False

def save_document(user_id,transcriptid,name):
    try:
        db.documents.insert_one({'user_id': user_id, 'transcript_id': transcriptid,"name":name})
    except Exception as e:
        print(f"Error saving document: {e}")
        return False
    return True

def get_document(user_id):
    try:
        document = db.documents.find_one({'user_id': user_id})
        if document:
            document['_id'] = str(document['_id'])
            document['transcript_id']=str(document['transcript_id'])
            return document
        else:
            return False
    except Exception as e:
        print(f"Error getting document: {e}")
        return False
    
def save_email_db(email):
    try:
        db.emails.insert_one({'email': email})
    except Exception as e:
        print(f"Error saving email: {e}")
        return False
    return True


def delete_document(user_id,transcriptid):
    try:
        db.transcripts.delete_one({'_id':ObjectId(transcriptid)})
        db.documents.delete_one({'user_id': user_id,'transcript_id':ObjectId(transcriptid)})
        return True
    except Exception as e:
        print(f"Error deleting document: {e}")
        return False   
# get all docs for a user
def get_all_documents(user_id):
    try:
        documents = db.documents.find({'user_id': user_id})
        documents = list(documents)
        for document in documents:
            document['_id'] = str(document['_id'])
        return documents
    except Exception as e:
        print(f"Error getting documents: {e}")
        return False  


def save_channel(user_id,channel_url):
    try:
        ans=db.channels.insert_one({'user_id': user_id, 'channel_url': channel_url})
    except Exception as e:
        print(f"Error saving channel: {e}")
        return False
    # return channel id
    return ans.inserted_id

def get_channels(user_id):
    channels = db.channels.find({'user_id': user_id}).sort("time_field", -1)
    channels = list(channels)
    for channel in channels:
        channel['_id'] = str(channel['_id'])
    return channels

def get_all_transcripts(user_id,channel_id):
    try:
        transcripts = db.transcripts.find({'user_id': user_id,'channel_id':channel_id})
        transcripts = list(transcripts)
        
        for transcript in transcripts:
            transcript['_id'] = str(transcript['_id'])
        
        return transcripts
    except Exception as e:
        print(f"Error getting transcripts: {e}")
        return False
    
# delete channel and all itss transcripts
def delete_channel_db(channel_id):
    try:
        first=db.channels.delete_one({'_id': ObjectId(channel_id)})
        second=db.transcripts.delete_many({'channel_id': channel_id})
        return True
    except Exception as e:
        print(f"Error deleting channel: {e}")
        return False
    
# chat id using userid and channel id and history
def add_session(user_id, channel_id,channel_url):
    try:
        utc_tz = pytz.UTC
        result = db.sessions.insert_one({'user_id': user_id, 'channel_id': channel_id, 'channel_url':channel_url,'timestamp': datetime.now(utc_tz)})
        session_id = result.inserted_id  # Get the inserted ID
        return str(session_id)  # Return the session ID as a string
    except Exception as e:
        print(f"Error adding chat session: {e}")
        return None
    
def update_session(user_id, channel_id, chatDetails):
    try:
        utc_tz = pytz.UTC
        update = {
            '$set': {
                'user_id': user_id,
                'channel_id': channel_id,
                'chatDetails': chatDetails,
                'timestamp': datetime.now(utc_tz)
            }
        }
        result = db.sessions.find_one_and_update({'user_id': user_id, 'channel_id': channel_id},update, upsert=True, new=True)
        return True  
    except Exception as e:
        print(f"Error adding chat session: {e}")
        return None
# get chat using userid and channel id
def get_session(user_id,channel_id):
    try:
        user_id = ObjectId(user_id)
        chat = db.sessions.find_one({'user_id': user_id,'channel_id':channel_id}).sort("time_field", -1)
        if chat:
            chat['_id'] = str(chat['_id'])
            return chat
        else:
            return False
    except Exception as e:
        print(f"Error getting chat: {e}")
        return False
# get all chatsid using userid
def get_all_sessions(user_id):
    try:
        chats = db.sessions.find({'user_id': user_id})
        chats = list(chats)
        for chat in chats:
            chat['_id'] = str(chat['_id'])
        return chats
    except Exception as e:
        print(f"Error getting chats: {e}")
        return False
    
def delete_session(session_id):
    try:
        db.sessions.delete_one({'_id': ObjectId(session_id)})
        return True
    except Exception as e:
        print(f"Error deleting session: {e}")
        return False
 
def delete_all_sessions(user_id):
    try:
        db.sessions.delete_many({'user_id': user_id})
        # db.channels.delete_many({'user_id': user_id})
        # db.transcripts.delete_many({'channel_id': channel_id})
        db.history.delete_many({'user_id':user_id})
        return True
    except Exception as e:
        print(f"Error deleting session: {e}")
        return False
 

def get_history(session_id,user_id):
    try:
        chat = db.history.find_one({'session_id': session_id ,'user_id':user_id})
        if chat:
            chat['_id'] = str(chat['_id'])
            return chat
        else:
            return False
    except Exception as e:
        print(f"Error getting history: {e}")
        return False
    
def set_history(session_id,history,user_id):
    try:
        db.history.update_one({'session_id': session_id ,'user_id':user_id}, {'$set': {
            'history': history
        }},upsert=True)
        return True
    except Exception as e:
        print(f"Error setting history: {e}")
        return False

