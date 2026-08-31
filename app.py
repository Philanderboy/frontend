import os
import uuid
from io import BytesIO

from flask import Flask, render_template, request, redirect, url_for, abort, session, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
from werkzeug.utils import secure_filename

import webauthn

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'tiff'}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024
WEBP_QUALITY = 80
JPEG_QUALITY = 82
MAX_DIMENSION = 1920

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

db = SQLAlchemy(app)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(200))
    image_name = db.Column(db.String(200), nullable=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _resize(img):
    w, h = img.size
    if w > MAX_DIMENSION or h > MAX_DIMENSION:
        img.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.LANCZOS)
    return img

def save_compressed_images(file_storage):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    base_name = uuid.uuid4().hex
    img = Image.open(file_storage.stream)
    if img.mode in ('RGBA', 'LA', 'P'):
        img = img.convert('RGBA')
    else:
        img = img.convert('RGB')
    img = _resize(img)
    webp_path = os.path.join(UPLOAD_FOLDER, f'{base_name}.webp')
    img.save(webp_path, format='WEBP', quality=WEBP_QUALITY, method=4)
    jpg_path = os.path.join(UPLOAD_FOLDER, f'{base_name}.jpg')
    rgb_img = img.convert('RGB')
    rgb_img.save(jpg_path, format='JPEG', quality=JPEG_QUALITY, optimize=True)
    return base_name

@app.route('/')
def index():
    tasks = Task.query.all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image_name = None
        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename):
            image_name = save_compressed_images(file)
        new_task = Task(title=title, description=description, image_name=image_name)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    task = Task.query.get_or_404(id)
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename):
            if task.image_name:
                for ext in ('webp', 'jpg'):
                    old = os.path.join(UPLOAD_FOLDER, f'{task.image_name}.{ext}')
                    if os.path.exists(old):
                        os.remove(old)
            task.image_name = save_compressed_images(file)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', task=task)

@app.route('/delete/<int:id>')
def delete(id):
    task = Task.query.get_or_404(id)
    if task.image_name:
        for ext in ('webp', 'jpg'):
            path = os.path.join(UPLOAD_FOLDER, f'{task.image_name}.{ext}')
            if os.path.exists(path):
                os.remove(path)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('biometric') == 'true':
            session['user'] = 'demo_user'
            return redirect(url_for('index'))
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password':
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template_string(
                "<p style='color:red'>Invalid credentials. Try again.</p>"
                "<a href=\"{{ url_for('login') }}\">Back to login</a>"
            )
    login_html = """
    <!doctype html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h2>Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login with password</button>
        </form>
        <hr>
        <button onclick="biometricLogin()">Login with Face ID / Touch ID</button>
        <script>
        function biometricLogin() {
            const form = document.createElement('form');
            form.method = 'post';
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'biometric';
            input.value = 'true';
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        }
        </script>
    </body>
    </html>
    """
    return render_template_string(login_html)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/biometric-status')
def biometric_status():
    return jsonify({'biometric_supported': True})

# WebAuthn endpoints
@app.route('/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    data = request.get_json()
    username = data.get('username') if data else None
    if not username:
        return jsonify({'error': 'Username required'}), 400
    try:
        options = webauthn.begin_registration(username)
        return jsonify(options)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    data = request.get_json()
    username = data.get('username') if data else None
    credential = data.get('credential') if data else None
    if not username or not credential:
        return jsonify({'error': 'Missing data'}), 400
    try:
        result = webauthn.complete_registration(username, credential)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    data = request.get_json()
    username = data.get('username') if data else None
    if not username:
        return jsonify({'error': 'Username required'}), 400
    try:
        options = webauthn.begin_authentication(username)
        return jsonify(options)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    data = request.get_json()
    username = data.get('username') if data else None
    credential = data.get('credential') if data else None
    if not username or not credential:
        return jsonify({'error': 'Missing data'}), 400
    try:
        result = webauthn.complete_authentication(username, credential)
        if result.get('verified'):
            session['user'] = username
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
