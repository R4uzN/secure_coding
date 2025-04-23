from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
import sqlite3
import uuid
from flask_socketio import SocketIO, emit
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key') 
DATABASE = 'my_market.db'
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 

csrf = CSRFProtect(app)  
socketio = SocketIO(app, cors_allowed_origins="*")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@socketio.on('send_message')        
def handle_send_message(data):
    if 'username' in data and 'message' in data and isinstance(data['message'], str):
        if 1 <= len(data['message']) <= 500:
            emit('broadcast_message', data, broadcast=True)

@app.context_processor
def inject_user():
    if 'user_id' in session:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        return dict(user=user)
    return dict(user=None)

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            is_suspended INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS product (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            seller_id TEXT NOT NULL,
            image TEXT,
            is_blocked INTEGER DEFAULT 0,
            FOREIGN KEY (seller_id) REFERENCES user (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES user (id),
            FOREIGN KEY (receiver_id) REFERENCES user (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS report (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reporter_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reporter_id) REFERENCES user (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transfer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES user (id),
            FOREIGN KEY (receiver_id) REFERENCES user (id)
        )
    ''')

    conn.commit()
    conn.close()
import os
from werkzeug.utils import secure_filename
from flask import abort

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 최대 5MB

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '0').strip()

        if not title or not description or not price.isdigit():
            flash('모든 필드를 올바르게 입력해주세요.')
            return redirect(url_for('new_product'))

        price = int(price)
        product_id = str(uuid.uuid4())

        image = request.files.get('image')
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO product (id, title, description, price, seller_id, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (product_id, title, description, price, session['user_id'], image_filename))
        conn.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('my_products'))

    return render_template('new_product.html')

@app.route('/transfer/<user_id>', methods=['GET', 'POST'])
def transfer_page(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] == user_id:
        flash("자기 자신에게는 송금할 수 없습니다.")
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    receiver = cursor.fetchone()

    if not receiver:
        flash("해당 사용자를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
            if amount <= 0:
                raise ValueError
        except (ValueError, TypeError):
            flash("송금 금액이 유효하지 않습니다.")
            return redirect(url_for('transfer_page', user_id=user_id))

        sender_id = session['user_id']
        cursor.execute('''
            INSERT INTO transfer (sender_id, receiver_id, amount)
            VALUES (?, ?, ?)
        ''', (sender_id, user_id, amount))
        conn.commit()
        flash(f"{receiver['username']}님께 {amount}원 송금했습니다.")
        return redirect(url_for('chat_list'))

    return render_template('transfer.html', receiver=receiver, user_id=user_id)

@app.route('/transactions')
def transaction_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT 
            t.*, 
            u1.username AS sender_name,
            u2.username AS receiver_name,
            CASE 
                WHEN t.sender_id = ? THEN 'sent'
                ELSE 'received'
            END as direction
        FROM transfer t
        JOIN user u1 ON t.sender_id = u1.id
        JOIN user u2 ON t.receiver_id = u2.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.timestamp DESC
    ''', (user_id, user_id, user_id))

    transactions = cursor.fetchall()

    return render_template('transactions.html', transactions=transactions)

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()

    if not product:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('my_products'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '0').strip()

        if not title or not description or not price.isdigit():
            flash('모든 필드를 올바르게 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        price = int(price)
        cursor.execute('''
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        ''', (title, description, price, product_id))
        conn.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('my_products'))

    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    conn.commit()

    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))


@app.route('/user/<user_id>')
def view_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    return render_template('user_profile.html', user=user)

@app.route('/chats')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT 
            CASE 
                WHEN sender_id = ? THEN receiver_id 
                ELSE sender_id 
            END as partner_id,
            MAX(timestamp) as last_time
        FROM chat
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY partner_id
        ORDER BY last_time DESC
    ''', (user_id, user_id, user_id))
    
    partners = cursor.fetchall()

    chat_partners = []
    for row in partners:
        cursor.execute("SELECT username FROM user WHERE id = ?", (row['partner_id'],))
        user = cursor.fetchone()
        chat_partners.append({
            'id': row['partner_id'],
            'username': user['username'] if user else '알 수 없음',
            'last_time': row['last_time']
        })

    return render_template('chat_list.html', partners=chat_partners)

@app.route('/chat/<user_id>', methods=['GET', 'POST'])
def start_chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    my_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    partner = cursor.fetchone()
    partner_name = partner['username'] if partner else '알 수 없음'

    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        if message:
            cursor.execute('''
                INSERT INTO chat (sender_id, receiver_id, message)
                VALUES (?, ?, ?)
            ''', (my_id, user_id, message))
            conn.commit()
        return redirect(url_for('start_chat', user_id=user_id))

    cursor.execute('''
        SELECT * FROM chat
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (my_id, user_id, user_id, my_id))
    messages = cursor.fetchall()

    return render_template('chat.html', target_id=user_id, partner_name=partner_name, messages=messages)


@app.route('/products')
def list_products():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
    ''')
    products = cursor.fetchall()
    return render_template('products.html', products=products)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 유효성 검사
        if not username or not password:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('register'))

        # 사용자명 조건: 영문/숫자/_ 만 허용
        if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
            flash('사용자명은 영문, 숫자, 밑줄(_)만 사용하며 3~32자여야 합니다.')
            return redirect(url_for('register'))

        # 비밀번호 조건: 최소 8자, 대소문자/숫자/특수문자 각 1개 이상
        if not re.match(
            r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]).{8,64}$',
            password):
            flash('비밀번호는 8자 이상, 대소문자, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)

        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        conn.commit()

        flash('회원가입 성공! 로그인해주세요.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('아이디와 비밀번호를 입력해주세요.')
            return redirect(url_for('login'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            if user['is_suspended']:
                flash("이 계정은 휴면 상태입니다.")
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        
        flash('아이디 또는 비밀번호가 틀렸습니다.')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    keyword = request.args.get('q', '').strip()
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if keyword:
        keyword = f"%{keyword}%"
        cursor.execute('''
            SELECT p.*, u.username as seller_name
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.is_blocked = 0 AND (
                p.title LIKE ? OR p.description LIKE ?
            )
        ''', (keyword, keyword))
    else:
        cursor.execute('''
            SELECT p.*, u.username as seller_name
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.is_blocked = 0
        ''')

    products = cursor.fetchall()

    return render_template('dashboard.html', user=user, products=products, keyword=keyword)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'update_bio':
            bio = request.form.get('bio', '').strip()
            if len(bio) > 500:
                flash("소개글은 500자 이내로 입력해주세요.")
            else:
                cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
                conn.commit()
                flash("소개글이 저장되었습니다.")

        elif action == 'change_pw':
            current_pw = request.form.get('current_pw', '').strip()
            new_pw = request.form.get('new_pw', '').strip()

            # 해시된 비밀번호 검증
            if not check_password_hash(user['password'], current_pw):
                flash("현재 비밀번호가 일치하지 않습니다.")
            # 복잡도 검사: 8자 이상, 대문자, 소문자, 숫자, 특수문자 포함
            elif not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', new_pw):
                flash("비밀번호는 8자 이상, 대소문자, 숫자, 특수문자를 포함해야 합니다.")
            else:
                hashed_pw = generate_password_hash(new_pw)
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
                conn.commit()
                flash("비밀번호가 안전하게 변경되었습니다.")

        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)
@app.route('/product/<product_id>')
def view_product(product_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    ''', (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    return render_template('view_product.html', product=product)


@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM product
        WHERE seller_id = ?
    ''', (session['user_id'],))
    products = cursor.fetchall()

    return render_template('my_products.html', products=products)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        target_type = request.form.get('target_type', '').strip()
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()

        if not target_type or not target_id or not reason:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('dashboard'))

        cursor.execute('''
            INSERT INTO report (target_type, target_id, reporter_id, reason)
            VALUES (?, ?, ?, ?)
        ''', (target_type, target_id, session['user_id'], reason))

        cursor.execute('''
            SELECT COUNT(*) FROM report
            WHERE target_type = ? AND target_id = ?
        ''', (target_type, target_id))
        report_count = cursor.fetchone()[0]

        if target_type == 'product' and report_count >= 3:
            cursor.execute('UPDATE product SET is_blocked = 1 WHERE id = ?', (target_id,))
            flash("신고가 누적되어 상품이 차단되었습니다.")
        elif target_type == 'user' and report_count >= 3:
            cursor.execute('UPDATE user SET is_suspended = 1 WHERE id = ?', (target_id,))
            flash("신고가 누적되어 사용자가 휴면 상태로 전환되었습니다.")

        conn.commit()
        return redirect(url_for('dashboard'))

    target_type = request.args.get('target_type', '').strip()
    target_id = request.args.get('target_id', '').strip()
    target_name = "알 수 없음"

    if target_type == 'product':
        cursor.execute("SELECT title FROM product WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        if row:
            target_name = row['title']
    elif target_type == 'user':
        cursor.execute("SELECT username FROM user WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        if row:
            target_name = row['username']

    return render_template('report.html',
                           target_type=target_type,
                           target_id=target_id,
                           target_name=target_name)


@app.route('/admin/reports')
def report_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] != get_admin_id():
        flash('관리자만 접근 가능합니다.')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, 
            u1.username AS reporter_name,
            u2.username AS reported_user_name,
            p.title AS reported_product_title
        FROM report r
        LEFT JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_type = 'user' AND r.target_id = u2.id
        LEFT JOIN product p ON r.target_type = 'product' AND r.target_id = p.id
        ORDER BY r.timestamp DESC
    ''')

    reports = cursor.fetchall()

    return render_template('admin_report_list.html', reports=reports)


@app.route('/admin/reports/delete/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if not current_user or current_user['username'] != 'admin':
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT target_type, target_id FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    if not report:
        flash("신고 내역이 존재하지 않습니다.")
        return redirect(url_for('report_list'))

    target_type = report['target_type']
    target_id = report['target_id']

    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))

    cursor.execute('''
        SELECT COUNT(*) FROM report
        WHERE target_type = ? AND target_id = ?
    ''', (target_type, target_id))
    remaining = cursor.fetchone()[0]

    if target_type == 'product' and remaining < 3:
        cursor.execute("UPDATE product SET is_blocked = 0 WHERE id = ?", (target_id,))
    elif target_type == 'user' and remaining < 3:
        cursor.execute("UPDATE user SET is_suspended = 0 WHERE id = ?", (target_id,))

    conn.commit()
    flash("신고가 삭제되었고, 차단 상태가 갱신되었습니다.")
    return redirect(url_for('report_list'))

@app.route('/admin/unsuspend/<user_id>', methods=['POST'])
def unsuspend_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] != get_admin_id():
        flash('관리자만 접근 가능합니다.')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("UPDATE user SET is_suspended = 0 WHERE id = ?", (user_id,))
    conn.commit()
    flash("해당 유저가 정상 계정으로 전환되었습니다.")
    return redirect(url_for('suspended_users'))


def get_admin_id():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM user WHERE username = 'admin'")
    row = cursor.fetchone()
    return row['id'] if row else None


@app.route('/admin/suspended-users')
def suspended_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] != get_admin_id():
        flash('관리자만 접근 가능합니다.')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE is_suspended = 1")
    users = cursor.fetchall()

    return render_template('admin_suspended_users.html', users=users)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃 되었습니다.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        init_db()

    socketio.run(app, debug=True)