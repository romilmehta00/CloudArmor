import os
import uuid
import bcrypt 
import boto3  
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect
from pymongo import MongoClient
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from botocore.config import Config
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# 1. Load Environment Variables BEFORE anything else
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key')

# 2. MongoDB Connection & Startup Check
MONGO_URI = os.environ.get('MONGO_URI')
client = MongoClient(MONGO_URI)

try:
    # Send a ping to confirm a successful connection
    client.admin.command('ping')
    print("✅ Successfully connected to MongoDB Atlas!")
except Exception as e:
    print(f"❌ MongoDB Connection Failed: {e}")
    print("Check your password, cluster URL, and ensure your IP is whitelisted (0.0.0.0/0).")

db = client['securevault']
users_col = db['users']
logs_col = db['logs']
files_col = db['files']
blocked_ips_col = db['blocked_ips']
login_attempts_col = db['login_attempts']

# 3. Secure AWS S3 Client
def get_s3_client():
    target_region = 'eu-north-1'
    return boto3.client(
        's3',
        region_name=target_region,
        # 's3v4' is mandatory for eu-north-1
        config=Config(
            signature_version='s3v4',
            s3={'addressing_style': 'virtual'} # Best practice for newer regions
        ),
        endpoint_url=f'https://s3.{target_region}.amazonaws.com',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    
S3_BUCKET = os.environ.get('S3_BUCKET')

# 4. Core Security Functions (IDS & Logging)
def log_activity(action, user=None, ip=None, details=None, threat_level='info'):
    logs_col.insert_one({
        'timestamp': datetime.utcnow(),
        'action': action,
        'user': user,
        'ip': ip or request.remote_addr,
        'details': details or '',
        'threat_level': threat_level
    })

def is_ip_blocked(ip):
    block = blocked_ips_col.find_one({'ip': ip})
    if block:
        if datetime.utcnow() < block['blocked_until']:
            return True
        else:
            blocked_ips_col.delete_one({'ip': ip})
    return False

def record_failed_attempt(ip, username):
    window_start = datetime.utcnow() - timedelta(minutes=10)
    login_attempts_col.insert_one({
        'ip': ip, 'username': username, 'timestamp': datetime.utcnow(), 'success': False
    })
    
    recent_fails = login_attempts_col.count_documents({
        'ip': ip, 'timestamp': {'$gte': window_start}, 'success': False
    })
 
    if recent_fails >= 5: # Max attempts before block
        block_until = datetime.utcnow() + timedelta(minutes=30)
        blocked_ips_col.update_one(
            {'ip': ip},
            {'$set': {'ip': ip, 'blocked_until': block_until, 'reason': 'brute_force'}},
            upsert=True
        )
        log_activity('IP_BLOCKED', ip=ip, details=f'{recent_fails} failed attempts', threat_level='critical')
        return True
    return False

def delete_user_and_data(target_user_id):
    # 1. Find all files belonging to the user
    user_files = list(files_col.find({'user_id': target_user_id}))
    
    # 2. Delete files from AWS S3
    if user_files:
        try:
            s3 = get_s3_client()
            for f in user_files:
                s3.delete_object(Bucket=S3_BUCKET, Key=f['s3_key'])
        except Exception as e:
            print(f"⚠️ S3 Cleanup Error during account deletion: {e}")

    # 3. Delete file metadata from MongoDB
    files_col.delete_many({'user_id': target_user_id})
    
    # 4. Delete the actual user record
    users_col.delete_one({'_id': target_user_id})

# 5. Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# 6. Page Routes

# 6. Page Routes
@app.route('/')
def index():
    # Show the new landing page
    return render_template('home.html')

@app.route('/auth')
def auth_page():
    # This was your old index.html (Login/Register)
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect('/auth') # Redirect to auth instead of root
    return render_template('dashboard.html')

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or not session.get('is_admin'): return redirect('/auth')
    return render_template('admin.html')
# @app.route('/')
# def index():
#     # Show the new landing page
#     return render_template('home.html')

# def index():
#     return render_template('index.html')

# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session: return redirect('/')
#     return render_template('dashboard.html')

# @app.route('/admin')
# def admin_panel():
#     if 'user_id' not in session or not session.get('is_admin'): return redirect('/')
#     return render_template('admin.html')

# 7. API Routes (Auth)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    ip = request.remote_addr

    if is_ip_blocked(ip):
        return jsonify({'error': 'Access denied. IP blocked.'}), 403

    user = users_col.find_one({'username': data.get('username')})
    if not user or not bcrypt.checkpw(data.get('password', '').encode('utf-8'), user['password']):
        record_failed_attempt(ip, data.get('username'))
        log_activity('LOGIN_FAILED', ip=ip, threat_level='warning')
        return jsonify({'error': 'Invalid credentials'}), 401

    login_attempts_col.delete_many({'ip': ip}) # Clear fails on success
    session.update({'user_id': user['_id'], 'username': user['username'], 'is_admin': user.get('is_admin', False)})
    log_activity('LOGIN_SUCCESS', user=user['username'], ip=ip)
    return jsonify({'is_admin': user.get('is_admin', False)})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if users_col.find_one({'$or': [{'username': data.get('username')}, {'email': data.get('email')}]}):
        return jsonify({'error': 'User exists'}), 409
        
    hashed = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
    users_col.insert_one({
        '_id': str(uuid.uuid4()), 'username': data.get('username'), 
        'email': data.get('email'), 'password': hashed, 'is_admin': False
    })

@app.route('/api/account/delete', methods=['DELETE'])
@login_required
def delete_my_account():
    user_id = session['user_id']
    username = session['username']
    
    # Call the cleanup helper
    delete_user_and_data(user_id)
    
    # Log the event and destroy the session
    log_activity('ACCOUNT_SELF_DELETED', user=username, ip=request.remote_addr, threat_level='warning')
    session.clear()
    
    return jsonify({'message': 'Your account and all associated files have been permanently deleted.'}), 200

    send_email(
        to_email=data.get('email'),
        subject="Welcome to CloudArmor!",
        body=f"Hello {data.get('username')},\n\nYour account has been successfully created. Welcome Abroad!"
    )

    return jsonify({'message': 'Created'}), 201

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

# 8. API Routes (AWS S3 Files)
@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    # 1. Get the file size FIRST before the stream is used
    file.seek(0, 2) # Move to the end of the file
    file_size = file.tell() # Get the current position (size)
    file.seek(0) # Reset the stream back to the beginning for the upload

    file_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1]
    s3_key = f"uploads/{session['user_id']}/{file_id}{ext}"

    try:
        s3 = get_s3_client()
        # 2. Now perform the upload
        s3.upload_fileobj(
            file,
            S3_BUCKET,
            s3_key,
            ExtraArgs={'ServerSideEncryption': 'AES256'}
        )
    except Exception as e:
        # If AWS fails, you still have the file_size recorded
        print(f"S3 Upload Error: {e}")
        s3_key = f"DEMO/{s3_key}"

    # 3. Store the metadata in MongoDB
    files_col.insert_one({
        '_id': file_id,
        'user_id': session['user_id'],
        'username': session['username'],
        'original_name': file.filename,
        's3_key': s3_key,
        'size': file_size,
        'uploaded_at': datetime.utcnow(),
        'content_type': file.content_type or 'application/octet-stream'
    })
    
    log_activity('FILE_UPLOADED', user=session['username'], ip=request.remote_addr,
                 details=f'File: {file.filename}, Size: {file_size}')
                 
    return jsonify({'message': 'File uploaded successfully', 'file_id': file_id, 'filename': file.filename})


@app.route('/api/files', methods=['GET'])
@login_required
def list_files():
    files = list(files_col.find({'user_id': session['user_id']}))
    for f in files: 
        f['file_id'] = f.pop('_id')
        f['uploaded_at'] = f['uploaded_at'].isoformat()
    return jsonify(files)

@app.route('/api/files/<file_id>/download', methods=['GET'])
@login_required
def download_file(file_id):
    file_meta = files_col.find_one({'_id': file_id, 'user_id': session['user_id']})
    if not file_meta: return jsonify({'error': 'Not found'}), 404
    try:
        s3 = get_s3_client()
        url = s3.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET, 'Key': file_meta['s3_key']}, ExpiresIn=300)
        return jsonify({'download_url': url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    file_meta = files_col.find_one({'_id': file_id, 'user_id': session['user_id']})
    try:
        get_s3_client().delete_object(Bucket=S3_BUCKET, Key=file_meta['s3_key']) # type: ignore
        files_col.delete_one({'_id': file_id})
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 9. API Routes (Admin)
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    return jsonify({
        'total_users': users_col.count_documents({}),
        'total_files': files_col.count_documents({}),
        'blocked_ips': blocked_ips_col.count_documents({}),
        'critical_events': logs_col.count_documents({'threat_level': 'critical'})
    })

@app.route('/api/admin/blocked-ips', methods=['GET'])
@admin_required
def admin_blocked_ips():
    blocked = list(blocked_ips_col.find())
    for b in blocked:
        b['_id'] = str(b['_id'])
        b['blocked_until'] = b['blocked_until'].isoformat()
    return jsonify(blocked)

@app.route('/api/admin/blocked-ips/<ip>/unblock', methods=['POST'])
@admin_required
def unblock_ip(ip):
    blocked_ips_col.delete_one({'ip': ip})
    return jsonify({'message': 'Unblocked'})

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def admin_logs():
    logs = list(logs_col.find().sort('timestamp', -1).limit(50))
    for l in logs:
        l['_id'] = str(l['_id'])
        l['timestamp'] = l['timestamp'].isoformat()
    return jsonify({'logs': logs})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    # Fetch all users, but exclude the password hash from the response for security
    users = list(users_col.find({}, {'password': 0}))
    for u in users:
        u['user_id'] = u.pop('_id') # Rename _id to user_id for the frontend
    return jsonify(users)

@app.route('/api/admin/users/<target_user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(target_user_id):
    # Prevent the admin from accidentally deleting themselves
    if target_user_id == session['user_id']:
        return jsonify({'error': 'You cannot delete your own admin account.'}), 400
        
    target_user = users_col.find_one({'_id': target_user_id})
    if not target_user:
        return jsonify({'error': 'User not found.'}), 404
        
    # Call the cleanup helper
    delete_user_and_data(target_user_id)
    
    # Log the administrative action
    log_activity(
        'ADMIN_DELETED_USER', 
        user=session['username'], 
        ip=request.remote_addr, 
        details=f"Deleted user: {target_user.get('username')}", 
        threat_level='critical'
    )
    
    return jsonify({'message': f"User {target_user.get('username')} and their files were deleted."}), 200

# 10. Initialization
def seed_admin():
    try:
        if not users_col.find_one({'username': 'admin'}):
            hashed = bcrypt.hashpw(b'Admin@12345', bcrypt.gensalt())
            users_col.insert_one({
                '_id': str(uuid.uuid4()), 'username': 'admin', 'password': hashed, 'is_admin': True
            })
            print("🛡️ Admin created: admin / Admin@12345")
    except Exception:
        pass # Silently fail if MongoDB isn't connected yet (avoids crashing the app)

def send_email(to_email, subject, body):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')

    # Fail gracefully if credentials aren't set
    if not smtp_user or not smtp_pass:
        print(f"⚠️ SMTP not configured. Skipped sending email to {to_email}")
        return False

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls() # Secure the connection
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

if __name__ == '__main__':
    seed_admin()
    app.run(debug=True, host='0.0.0.0', port=5000)