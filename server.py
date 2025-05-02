from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
from datetime import datetime, date

app = Flask(__name__)
CORS(app)


# ======================================
# MySQL config + reconnect helpers
# ======================================
def make_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="NAITS",
        password="N45192091425Ea@",
        database="naits_users",
        autocommit=True
    )

# initial connection
db = make_db_connection()

def reconnect_db():
    global db
    try:
        db.close()
    except:
        pass
    db = make_db_connection()

def get_cursor():
    try:
        db.ping(reconnect=True, attempts=3, delay=2)
    except mysql.connector.Error:
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
def dashboard_stats():
    cursor = get_cursor()
    today = date.today()
    cursor.execute("SELECT COUNT(*) AS c FROM users")
    total_users = cursor.fetchone()['c']
    cursor.execute(
        "SELECT COUNT(*) AS c FROM user_logins WHERE DATE(login_time) = %s",
        (today,)
    )
    logins_today = cursor.fetchone()['c']
    try:
        cursor.execute(
            "SELECT COUNT(*) AS c FROM user_login_failures WHERE DATE(attempt_time) = %s",
            (today,)
        )
        failed_logins = cursor.fetchone()['c']
    except:
        failed_logins = 0
    cursor.execute(
        "SELECT COUNT(*) AS c FROM users WHERE DATE(created_at) = %s",
        (today,)
    )
    signups_today = cursor.fetchone()['c']
    cursor.execute("""
        SELECT COUNT(*) AS c
        FROM users
        WHERE last_login IS NOT NULL
          AND (last_logout IS NULL OR last_login > last_logout)
    """
    )
    active_users = cursor.fetchone()['c']
    cursor.execute("SELECT department, COUNT(*) c FROM users GROUP BY department")
    dept_counts = {r['department']: r['c'] for r in cursor.fetchall()}
    cursor.execute("SELECT level, COUNT(*) c FROM users GROUP BY level")
    lvl_counts = {r['level']: r['c'] for r in cursor.fetchall()}
    cursor.execute("""
        SELECT u.nickname, ul.login_time
        FROM user_logins ul
        JOIN users u ON ul.user_id = u.id
        ORDER BY ul.login_time DESC
        LIMIT 10
    """
    )
    recent = [
        {
            'timestamp': r['login_time'].strftime('%Y-%m-%d %H:%M:%S'),
            'description': f"{r['nickname']} logged in"
        }
        for r in cursor.fetchall()
    ]
    return jsonify({
        'total_users': total_users,
        'logins_today': logins_today,
        'failed_logins_today': failed_logins,
        'signups_today': signups_today,
        'active_users': active_users,
        'department_counts': dept_counts,
        'level_counts': lvl_counts,
        'recent_events': recent
    })

# ======================================
# Public Announcements
# ======================================
@app.route('/add_announcement', methods=['POST'])
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
def get_announcements():
    cursor = get_cursor()
    cursor.execute("""
        SELECT id, title, message,
               DATE_FORMAT(date_posted, '%%M %%d, %%Y') AS date,
               DATE_FORMAT(date_posted, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
        FROM announcements
        ORDER BY date_posted DESC
    """)
    return jsonify(cursor.fetchall())


# ======================================
# Admin Announcements API
# ======================================
API_BASE = '/api/announcements'

@app.route(API_BASE, methods=['GET'])
def api_list_announcements():
    cursor = get_cursor()
    cursor.execute("""
        SELECT
          id,
          title,
          message,
          DATE_FORMAT(date_posted, '%%M %%d, %%Y') AS date,
          is_new
        FROM announcements
        ORDER BY date_posted DESC, id DESC
    """
    )
    rows = cursor.fetchall()
    return jsonify(rows)
@app.route(API_BASE, methods=['POST'])
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
        INSERT INTO announcements (title, message, date_posted, is_new)
        VALUES (%s, %s, NOW(), %s)
        """,
        (title, message, int(is_new))
    )
    return jsonify({'status': 'success'}), 201

@app.route(f"{API_BASE}/<int:ann_id>", methods=['GET'])
def api_get_announcement(ann_id):
    cursor = get_cursor()
    cursor.execute("""
      SELECT id, title, message, date_posted
             DATE_FORMAT(date_posted, '%%M %%d, %%Y') AS date,
             is_new
      FROM announcements
      WHERE id = %s
    """, (ann_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'status':'error','message':'Not found'}), 404
    return jsonify(row), 200


@app.route(f"{API_BASE}/<int:ann_id>", methods=['DELETE'])
def api_delete_announcement(ann_id):
    cursor = get_cursor()
    cursor.execute("DELETE FROM announcements WHERE id=%s", (ann_id,))
    if cursor.rowcount == 0:
        return jsonify({'status':'error','message':'Not found'}), 404
    return jsonify({'status':'success'})


if __name__ == '__main__':
    app.run(debug=True)
