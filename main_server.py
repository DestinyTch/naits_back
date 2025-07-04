import mysql.connector
from mysql.connector import Error
import bcrypt
import os
from dateutil.relativedelta import relativedelta
from flask import Flask, request, jsonify, url_for, render_template,  send_from_directory, abort
from flask_cors import CORS, cross_origin


from datetime import datetime, date,timedelta
import requests

from werkzeug.utils import secure_filename

API_BASE_URL = 'https://naits-back-2.onrender.com'
app = Flask(__name__)
# Allow React/JS origin for all /api/* endpoints
global_origin = "*"
CORS(app, resources={r"/api/*": {"origins": global_origin}})

    
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def fetch_from_api(path):
    """
    Fetches JSON from your own API.
    """
    url = f"{API_BASE_URL}{path}"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()


BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXT = {'png','jpg','jpeg','gif','pdf','mp4','docx'}

def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

# ======================================
# MySQL config + reconnect helpers
# ======================================
def make_db_connection():
    return mysql.connector.connect(
        host="standard1.afeeshost.com ",
        user="destinyt_user",
        password="D45192091425Ea@",
        port= 3306,
        database="destinyt_naits",
        autocommit=True
    )

# initial connection
db = make_db_connection()

def reconnect_db():
    global db
    try:
        if db.is_connected():
            db.close()
    except Exception:
        pass
    db = make_db_connection()

def get_cursor():
    global db
    try:
        db.ping(reconnect=True, attempts=3, delay=2)
    except Error as e:
        print(f"[DB] Lost connection: {e}. Reconnecting...")
        reconnect_db()
    return db.cursor(dictionary=True)
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma']        = 'no-cache'
    response.headers['Expires']       = '0'
    return response

# ======================================
# User routes
# ======================================
@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    cursor = get_cursor()
    data = request.get_json() or {}
    required = ['firstName','lastName','whatsapp','nickname','level','department','password']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'status':'error','message':f'Missing: {", ".join(missing)}'}), 400

    cursor.execute(
        "SELECT id FROM users WHERE nickname=%s OR whatsapp=%s",
        (data['nickname'], data['whatsapp'])
    )
    if cursor.fetchone():
        return jsonify({'status':'error','message':'Already registered'}), 409

    pw_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    cursor.execute(
        """
        INSERT INTO users
          (first_name, last_name, whatsapp, nickname, level, department, password)
        VALUES
          (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            data['firstName'], data['lastName'],
            data['whatsapp'], data['nickname'],
            data['level'], data['department'],
            pw_hash
        )
    )
    return jsonify({'status':'success','message':'Registered'})

@app.route('/users', methods=['GET'])
@cross_origin()
def get_users():
    cursor = get_cursor()
    cursor.execute("""
        SELECT
          id,
          first_name, last_name,
          whatsapp, nickname,
          level, department,
          DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
          IFNULL(DATE_FORMAT(last_login, '%Y-%m-%d %H:%i:%s'), '') AS last_login
        FROM users
        ORDER BY created_at DESC
    """
    )
    return jsonify(cursor.fetchall())

@app.route('/update_user', methods=['PUT'])
@cross_origin()
def update_user():
    cursor = get_cursor()
    data = request.get_json() or {}
    orig = data.get('nickname')
    new_nick = data.get('nicknameNew')

    cursor.execute("SELECT id FROM users WHERE nickname=%s", (orig,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'status':'error','message':'User not found'}), 404

    uid = row['id']
    fields, vals = [], []
    mapping = {
        'firstName': 'first_name',
        'lastName': 'last_name',
        'whatsapp':  'whatsapp',
        'level':     'level',
        'department':'department',
    }
    for k, col in mapping.items():
        if data.get(k):
            fields.append(f"{col} = %s")
            vals.append(data[k])
    if new_nick:
        fields.append("nickname = %s")
        vals.append(new_nick)
    if data.get('password'):
        pwd_h = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
        fields.append("password = %s")
        vals.append(pwd_h)

    vals.append(uid)
    sql = f"UPDATE users SET {', '.join(fields)} WHERE id = %s"
    cursor.execute(sql, tuple(vals))
    return jsonify({'status':'success','message':'User updated'})

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    cursor = get_cursor()
    data = request.get_json() or {}
    cursor.execute("SELECT * FROM users WHERE nickname=%s", (data.get('nickname'),))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(data.get('password','').encode(), user['password'].encode()):
        now = datetime.now()
        cursor.execute("UPDATE users SET last_login=%s WHERE id=%s", (now, user['id']))
        cursor.execute(
            "INSERT INTO user_logins (user_id, login_time) VALUES (%s, %s)",
            (user['id'], now)
        )
        return jsonify({
            'status':'success',
            'user': {
                'id': user['id'],
                'nickname': user['nickname'],
                'last_login': now.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    return jsonify({'status':'error','message':'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@cross_origin()
def logout():
    cursor = get_cursor()
    data = request.get_json() or {}
    uid = data.get('user_id')
    if not uid:
        return jsonify({'status':'error','message':'user_id required'}), 400
    now = datetime.now()
    cursor.execute("UPDATE users SET last_logout=%s WHERE id=%s", (now, uid))
    return jsonify({'status':'success','message':'Logged out'})

@app.route('/delete_account', methods=['POST'])
@cross_origin()
def delete_account():
    cursor = get_cursor()
    data = request.get_json() or {}
    nick = data.get('nickname')
    if not nick:
        return jsonify({'status':'error','message':'Nickname required'}), 400
    cursor.execute("SELECT id FROM users WHERE nickname=%s", (nick,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'status':'error','message':'User not found'}), 404
    uid = row['id']
    cursor.execute("DELETE FROM user_logins WHERE user_id=%s", (uid,))
    cursor.execute("DELETE FROM users WHERE id=%s", (uid,))
    return jsonify({'status':'success','message':'Deleted'})

@app.route('/dashboard_stats', methods=['GET'])
@cross_origin()
def dashboard_stats():
    cursor = get_cursor()
    today = date.today()

    # Users
    cursor.execute("SELECT COUNT(*) AS c FROM users")
    total_users = cursor.fetchone()['c']

    # Logins today
    cursor.execute(
        "SELECT COUNT(*) AS c FROM user_logins WHERE DATE(login_time) = %s",
        (today,)
    )
    logins_today = cursor.fetchone()['c']

    # Failed logins today
    try:
        cursor.execute(
            "SELECT COUNT(*) AS c FROM user_login_failures WHERE DATE(attempt_time) = %s",
            (today,)
        )
        failed_logins = cursor.fetchone()['c']
    except:
        failed_logins = 0

    # Signups today
    cursor.execute(
        "SELECT COUNT(*) AS c FROM users WHERE DATE(created_at) = %s",
        (today,)
    )
    signups_today = cursor.fetchone()['c']

    # Active users
    cursor.execute("""
        SELECT COUNT(*) AS c
        FROM users
        WHERE last_login IS NOT NULL
          AND (last_logout IS NULL OR last_login > last_logout)
    """)
    active_users = cursor.fetchone()['c']

    # Dept & level breakdowns
    cursor.execute("SELECT department, COUNT(*) c FROM users GROUP BY department")
    dept_counts = {r['department']: r['c'] for r in cursor.fetchall()}
    cursor.execute("SELECT level, COUNT(*) c FROM users GROUP BY level")
    lvl_counts = {r['level']: r['c'] for r in cursor.fetchall()}

    # Recent login events
    cursor.execute("""
        SELECT u.nickname, ul.login_time
        FROM user_logins ul
        JOIN users u ON ul.user_id = u.id
        ORDER BY ul.login_time DESC
        LIMIT 10
    """)
    recent = [
        {
            'timestamp': r['login_time'].strftime('%Y-%m-%d %H:%M:%S'),
            'description': f"{r['nickname']} logged in"
        }
        for r in cursor.fetchall()
    ]

    # ** New: total messages **
    cursor.execute("SELECT COUNT(*) AS c FROM messages")
    message_count = cursor.fetchone()['c']
# 2) Ads count
    cursor.execute("SELECT COUNT(*) AS c FROM ads")
    ad_count = cursor.fetchone()['c']

    # 3) Resources count
    cursor.execute("SELECT COUNT(*) AS c FROM resources")
    resource_count = cursor.fetchone()['c']

    # 4) Announcements count
    cursor.execute("SELECT COUNT(*) AS c FROM announcements")
    announcement_count = cursor.fetchone()['c']
    # ** New: timestamp **
    last_updated = datetime.utcnow().isoformat() + 'Z'

    return jsonify({
           'total_users': total_users,
        'logins_today': logins_today,
        'failed_logins_today': failed_logins,
        'signups_today': signups_today,
        'active_users': active_users,
        'message_count': message_count,
        'ad_count': ad_count,
        'resource_count': resource_count,
        'announcement_count': announcement_count,
        'department_counts': dept_counts,
        'level_counts': lvl_counts,
        'recent_events': recent,
        'last_updated': last_updated
    })
@app.route('/logins_timeseries')
@cross_origin()
def logins_timeseries():
    days = int(request.args.get('days', 7))
    cursor = get_cursor()

    labels = []
    counts = []

    for i in range(days-1, -1, -1):
        d = date.today() - timedelta(days=i)
        cursor.execute(
            "SELECT COUNT(*) AS c FROM user_logins WHERE DATE(login_time) = %s",
            (d,)
        )
        labels.append(d.strftime('%Y-%m-%d'))
        counts.append(cursor.fetchone()['c'])

    return jsonify({ 'dates': labels, 'counts': counts })
# ======================================
# Public Announcements
# ======================================
@app.route('/add_announcement', methods=['POST'])
@cross_origin()
def add_announcement():
    cursor = get_cursor()
    data = request.get_json() or {}
    
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()

    if not title or not message:
        return jsonify({
            'status': 'error',
            'message': 'Title and message are required'
        }), 400

    dt = datetime.today()  # Use current date/time

    cursor.execute(
        "INSERT INTO announcements (title, message, date_posted) VALUES (%s, %s, %s)",
        (title, message, dt)
    )

    return jsonify({
        'status': 'success',
        'message': 'Announcement posted'
    })
@app.route('/announcements', methods=['GET'])
@cross_origin()
def get_announcements():
    cursor = get_cursor()
    cursor.execute("""
        SELECT id, title, message,
               DATE_FORMAT(created_at, '%%M %%d, %%Y') AS date,
               DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
        FROM announcements
        ORDER BY created_at DESC
    """)
    return jsonify(cursor.fetchall())


# ======================================
# Admin Announcements API
# ======================================
API_BASE = '/api/announcements'

@app.route(API_BASE, methods=['GET'])
@cross_origin()
def api_list_announcements():
    cursor = get_cursor()
    cursor.execute("""
        SELECT
          id,
          title,
          message,
          DATE_FORMAT(created_at, '%%M %%d, %%Y') AS date,
          is_new
        FROM announcements
        ORDER BY created_at DESC, id DESC
    """
    )
    rows = cursor.fetchall()
    return jsonify(rows)
@app.route(API_BASE, methods=['POST'])
@cross_origin()
def api_create_announcement():
    cursor = get_cursor()
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()
    is_new = bool(data.get('isNew'))

    if not (title and message):
        return jsonify({'status': 'error', 'message': 'Title and message are required'}), 400

    cursor.execute(
        """
        INSERT INTO announcements (title, message, created_at, is_new)
        VALUES (%s, %s, NOW(), %s)
        """,
        (title, message, int(is_new))
    )
    return jsonify({'status': 'success'}), 201
@app.route(f"{API_BASE}/<int:ann_id>", methods=['GET'])
@cross_origin()
def api_get_announcement(ann_id):
    cursor = get_cursor()
    cursor.execute("""
      SELECT
        id,
        title,
        message,
        DATE_FORMAT(created_at, '%%M %%d, %%Y') AS date,
        is_new
      FROM announcements
      WHERE id = %s
    """, (ann_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'status':'error','message':'Not found'}), 404
    return jsonify(row), 200


@app.route(f"{API_BASE}/<int:ann_id>", methods=['DELETE'])
@cross_origin()
def api_delete_announcement(ann_id):
    cursor = get_cursor()
    cursor.execute("DELETE FROM announcements WHERE id=%s", (ann_id,))
    if cursor.rowcount == 0:
        return jsonify({'status':'error','message':'Not found'}), 404
    return jsonify({'status':'success'})
@app.route(f"{API_BASE}/<int:ann_id>", methods=['PUT'])
@cross_origin()
def api_update_announcement(ann_id):
    cursor = get_cursor()
    data = request.get_json() or {}
    title   = data.get('title','').strip()
    message = data.get('message','').strip()
    if not title or not message:
        return jsonify({'status':'error','message':'Title and message are required'}), 400

    # optional flag
    is_new_flag = None
    if 'isNew' in data:
        is_new_flag = 1 if data['isNew'] else 0

    sql    = "UPDATE announcements SET title=%s, message=%s"
    params = [title, message]
    if is_new_flag is not None:
        sql += ", is_new=%s"
        params.append(is_new_flag)
    sql += " WHERE id=%s"
    params.append(ann_id)

    cursor.execute(sql, tuple(params))
    # ← this is the one you might have missed:
    make_db_connection().commit()    # or mysql.connection.commit(), etc.

    if cursor.rowcount == 0:
        return jsonify({'status':'error','message':'Announcement not found'}), 404

    return jsonify({'status':'success','message':'Announcement updated'}), 200











@app.route('/api/ads', methods=['POST'])
@cross_origin()
def create_ad():
    data  = request.form
    image = request.files.get('image')
    required = ['title', 'message', 'link_url', 'price', 'posted_by', 'duration_value', 'duration_unit']

    missing = [f for f in required if not data.get(f)]
    if not image or image.filename == '':
        missing.append('image')
    if missing:
        return jsonify({'status':'error', 'message':f"Missing: {', '.join(missing)}"}), 400

    # Duration validation
    try:
        value = int(data['duration_value'])
        if value < 1:
            raise ValueError
    except ValueError:
        return jsonify({'status':'error','message':'Invalid duration value'}), 400

    if not allowed_file(image.filename):
        return jsonify({'status':'error','message':'Invalid image type'}), 400

    filename = secure_filename(image.filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    image.save(os.path.join(UPLOAD_DIR, filename))

    now  = datetime.utcnow()
    unit = data['duration_unit']
    if unit == 'seconds':
        expires = now + timedelta(seconds=value)
    elif unit == 'minutes':
        expires = now + timedelta(minutes=value)
    elif unit == 'hours':
        expires = now + timedelta(hours=value)
    elif unit == 'days':
        expires = now + timedelta(days=value)
    elif unit == 'years':
        expires = now + relativedelta(years=value)
    else:
        return jsonify({'status':'error','message':'Invalid duration unit'}), 400

    cursor = get_cursor()
    cursor.execute("""
        INSERT INTO ads
          (title, message, image_filename, link_url, badge_label,
           price, posted_by, date_posted, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        data['title'], data['message'], filename, data['link_url'],
        data.get('badge_label',''), data['price'], data['posted_by'],
        now, expires
    ))
    return jsonify({'status':'success','id':cursor.lastrowid}), 201

@app.route('/api/ads', methods=['GET'])
@cross_origin()
def list_ads():
    cursor = get_cursor()
    cursor.execute("""
        SELECT id, title, message, image_filename, link_url, badge_label,
               price, posted_by, date_posted, expires_at
          FROM ads
      ORDER BY date_posted DESC
    """)
    ads = []
    for row in cursor.fetchall():
        ad = dict(row)
        ad['date_posted'] = ad['date_posted'].isoformat()
        ad['expires_at']  = ad['expires_at'].isoformat()
        ad['image_url']   = url_for('static',
            filename=f'uploads/{ad["image_filename"]}', _external=True)
        ads.append(ad)
    return jsonify(ads), 200

@app.route('/api/ads/<int:ad_id>', methods=['GET'])
@cross_origin()
def get_ad(ad_id):
    cursor = get_cursor()
    cursor.execute("""
        SELECT id, title, message, image_filename, link_url, badge_label,
               price, posted_by, date_posted, expires_at
          FROM ads
         WHERE id = %s
    """, (ad_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'error':'Not found'}), 404
    ad = dict(row)
    ad['date_posted'] = ad['date_posted'].isoformat()
    ad['expires_at']  = ad['expires_at'].isoformat()
    ad['image_url']   = url_for('static',
        filename=f'uploads/{ad["image_filename"]}', _external=True)
    return jsonify(ad), 200

@app.route('/api/ads/<int:ad_id>', methods=['PUT'])
@cross_origin()
def update_ad(ad_id):
    data = request.get_json() or {}
    fields = ['title','message','link_url','badge_label','price','posted_by']
    if not all(data.get(f,'').strip() for f in fields):
        return jsonify({'error':'Missing required fields'}), 400

    expires_at = None
    if 'duration_value' in data and 'duration_unit' in data:
        try:
            val = int(data['duration_value'])
            if val < 1:
                raise ValueError
        except ValueError:
            return jsonify({'error':'Invalid duration value'}), 400

        now = datetime.utcnow()
        u   = data['duration_unit']
        if u == 'seconds':
            expires_at = now + timedelta(seconds=val)
        elif u == 'minutes':
            expires_at = now + timedelta(minutes=val)
        elif u == 'hours':
            expires_at = now + timedelta(hours=val)
        elif u == 'days':
            expires_at = now + timedelta(days=val)
        elif u == 'years':
            expires_at = now + relativedelta(years=val)
        else:
            return jsonify({'error':'Invalid duration unit'}), 400

    sql = """
        UPDATE ads
           SET title=%s, message=%s, link_url=%s, badge_label=%s,
               price=%s, posted_by=%s""" + \
          (", expires_at=%s" if expires_at else "") + " WHERE id=%s"

    params = [
        data['title'], data['message'], data['link_url'],
        data['badge_label'], data['price'], data['posted_by']
    ]
    if expires_at:
        params.append(expires_at)
    params.append(ad_id)

    cursor = get_cursor()
    cursor.execute(sql, tuple(params))
    return jsonify({'status':'updated'}), 200

@app.route('/api/ads/<int:ad_id>', methods=['DELETE'])
@cross_origin()
def delete_ad(ad_id):
    cursor = get_cursor()
    cursor.execute("DELETE FROM ads WHERE id = %s", (ad_id,))
    if cursor.rowcount == 0:
        return jsonify({'status':'error','message':'Ad not found'}), 404
    return jsonify({'status':'deleted'}), 200


@app.route('/api/resources', methods=['POST'])
@cross_origin()
def api_create_resource():
    resource_type = request.form.get('resource_type')   # LectureNotes or PastQuestions
    level         = request.form.get('level')
    department    = request.form.get('department')
    course_code   = request.form.get('course_code', '').strip()
    course_title  = request.form.get('course_title', '').strip()
    link_text     = request.form.get('link_text', 'View').strip()
    file          = request.files.get('file')

    missing = [f for f in ('resource_type','level','department','course_code','course_title')
               if not locals()[f]]
    if not file or file.filename == '':
        missing.append('file')
    if missing:
        return jsonify({'status':'error','message': f"Missing: {', '.join(missing)}"}), 400

    if not allowed_file(file.filename):
        return jsonify({'status':'error','message':'Invalid file type'}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    fname = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, fname)
    file.save(file_path)

    cursor, conn = get_cursor()
    cursor.execute("""
      INSERT INTO resources
        (resource_type, level, department, course_code, course_title, link_text, file_name)
      VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (resource_type, level, department, course_code, course_title, link_text, fname))
    conn.commit()   # ← make sure to persist!
    new_id = cursor.lastrowid
    cursor.close()
    conn.close()

    return jsonify({'status':'success','id': new_id}), 201

@app.route('/api/resources', methods=['GET'])
@cross_origin()
def api_list_resources():
    resource_type = request.args.get('resource_type')
    level         = request.args.get('level')
    department    = request.args.get('department')

    sql = "SELECT * FROM resources WHERE 1=1"
    params = []
    if resource_type:
        sql += " AND resource_type=%s"; params.append(resource_type)
    if level:
        sql += " AND level=%s";         params.append(level)
    if department:
        sql += " AND department=%s";    params.append(department)
    sql += " ORDER BY uploaded_at DESC"

    cursor, conn = get_cursor()
    cursor.execute(sql, tuple(params))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    for r in rows:
        r['file_url'] = url_for('static',
                                filename=f"uploads/resources/{r['file_name']}",
                                _external=True)
    return jsonify(rows)

@app.route('/api/resources/<int:rid>', methods=['PUT'])
@cross_origin()
def api_update_resource(rid):
    data = request.get_json() or {}
    fields, vals = [], []
    for k, col in (('resource_type','resource_type'),
                   ('level','level'),
                   ('department','department'),
                   ('course_code','course_code'),
                   ('course_title','course_title'),
                   ('link_text','link_text')):
        if k in data:
            fields.append(f"{col}=%s")
            vals.append(data[k])
    if not fields:
        return jsonify({'status':'error','message':'No fields to update'}), 400

    vals.append(rid)
    sql = f"UPDATE resources SET {', '.join(fields)} WHERE id=%s"
    cursor, conn = get_cursor()
    cursor.execute(sql, tuple(vals))
    if cursor.rowcount == 0:
        cursor.close(); conn.close()
        return jsonify({'status':'error','message':'Not found'}), 404
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'status':'success'}), 200

@app.route('/api/resources/<int:rid>', methods=['DELETE'])
@cross_origin()
def api_delete_resource(rid):
    cursor, conn = get_cursor()
    cursor.execute("DELETE FROM resources WHERE id=%s", (rid,))
    if cursor.rowcount == 0:
        cursor.close(); conn.close()
        return jsonify({'status':'error','message':'Not found'}), 404
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'status':'success'}), 200

#
# ——— Public “show materials” ———
#

@app.route('/materials/<level>/<dept>')
@cross_origin()
def show_materials(level, dept):
    resource_type = request.args.get('type')
    if resource_type not in ('LectureNotes', 'PastQuestions'):
        abort(400, description="Invalid or missing ?type=LectureNotes|PastQuestions")

    # Build page title
    type_label = 'Lecture Notes' if resource_type == 'LectureNotes' else 'Past Questions'
    title = f"{dept.upper()} {level} - {type_label}"

    # Query the same DB directly
    cursor, conn = get_cursor()
    cursor.execute("""
       SELECT course_code, course_title, resource_type, link_text, file_name
       FROM resources
       WHERE level=%s AND department=%s AND resource_type=%s
       ORDER BY uploaded_at DESC
    """, (level, dept, resource_type))
    rows = cursor.fetchall()
    cursor.close(); conn.close()

    resources = []
    for r in rows:
        file_url = url_for('static',
                           filename=f"uploads/resources/{r['file_name']}",
                           _external=True)
        entry = {
            'course_code': r['course_code'],
            'course_title': r['course_title'],
            'type':        r['resource_type'],
            'file_url':    file_url,
            'link_text':   r.get('link_text', 'View')
        }
        if r['resource_type'] == 'PastQuestions':
            entry['files'] = [{'name': r['course_title'], 'url': file_url}]
        resources.append(entry)

    return render_template('materials.html',
                           title=title,
                           resources=resources)

@app.route('/select-materials')
@cross_origin()
def select_materials():
    return render_template('select_materials.html')

@app.route('/api/messages', methods=['POST'])
@cross_origin()
def api_create_message():
    cursor = get_cursor()
    data = request.get_json() or {}

    # Validate required fields
    required = ['firstName', 'lastName', 'messageType', 'message']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'status': 'error', 'message': f"Missing fields: {', '.join(missing)}"}), 400

    # Extract values
    first    = data['firstName'].strip()
    last     = data['lastName'].strip()
    whatsapp = data.get('whatsapp', '').strip()
    nick     = data.get('nickname', '').strip()
    level    = data.get('level', '').strip()
    dept     = data.get('department', '').strip()
    mtype    = data['messageType']
    msg      = data['message'].strip()
    created_at = data.get('createdAt') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute(
        """
        INSERT INTO messages
          (first_name, last_name, whatsapp, nickname, level, department, message_type, message, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (first, last, whatsapp, nick, level, dept, mtype, msg, created_at)
    )
    db.commit()

    return jsonify({'status': 'success', 'message': 'Message sent..you will be replied shortly'}), 201

# List messages
# List messages
@app.route('/api/messages', methods=['GET'])
@cross_origin()
def api_get_messages():
    cursor = get_cursor()
    cursor.execute(
        """
        SELECT
          id, first_name, last_name, whatsapp, nickname,
          level, department, message_type, message,
          DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
          replied,
          DATE_FORMAT(replied_at, '%Y-%m-%d %H:%i:%s') AS replied_at
        FROM messages
        ORDER BY created_at DESC
        """
    )
    rows = cursor.fetchall()
    return jsonify(rows), 200



@app.route('/api/messages/<int:msg_id>/replied', methods=['PUT'])
@cross_origin()
def mark_message_replied(msg_id):
    cursor = get_cursor()
    cursor.execute("UPDATE messages SET replied = 1, replied_at = NOW() WHERE id = %s", (msg_id,))
    db.commit()
    return jsonify({'status': 'success', 'message': 'Marked as replied'}), 200

@app.route('/api/messages/<int:msg_id>', methods=['DELETE'])
def api_delete_message(msg_id):
    cursor = get_cursor()
    cursor.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
    if cursor.rowcount == 0:
        return jsonify({'status': 'error', 'message': 'Message not found'}), 404
    db.commit()  # Use the global db object
    return jsonify({'status': 'success', 'message': 'Deleted'}), 200

@app.route('/api/messages/count', methods=['GET'])
@cross_origin()
def api_get_message_count():
    cursor = get_cursor()
    cursor.execute("SELECT COUNT(*) AS c FROM messages")
    count = cursor.fetchone()['c']
    return jsonify({'message_count': count}), 200
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
