import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# -------------------- Configuration --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit (adjust as needed)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------- Server master key --------------------
# This key is used to encrypt per-file symmetric keys in the DB.
# For production: load from a secure environment variable / KMS.
MASTER_KEY_FILE = os.path.join(BASE_DIR, "server_master.key")
if os.path.exists(MASTER_KEY_FILE):
    with open(MASTER_KEY_FILE, "rb") as f:
        MASTER_KEY = f.read().strip()
else:
    MASTER_KEY = Fernet.generate_key()
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(MASTER_KEY)
master_fernet = Fernet(MASTER_KEY)

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    files = db.relationship("File", backref="owner", lazy=True)
    file_keys = db.relationship("FileKey", backref="user", lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(300), nullable=False)
    stored_filename = db.Column(db.String(300), nullable=False)  # filename on disk
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    file_keys = db.relationship("FileKey", backref="file", lazy=True, cascade="all, delete-orphan")

class FileKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enc_file_key = db.Column(db.LargeBinary, nullable=False)   # file_key encrypted with MASTER_KEY
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------- Login loader --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Helpers --------------------
def generate_file_key():
    return Fernet.generate_key()  # bytes

def encrypt_file_bytes(file_bytes: bytes, file_key: bytes) -> bytes:
    f = Fernet(file_key)
    return f.encrypt(file_bytes)

def decrypt_file_bytes(enc_bytes: bytes, file_key: bytes) -> bytes:
    f = Fernet(file_key)
    return f.decrypt(enc_bytes)

def encrypt_file_key_for_db(file_key: bytes) -> bytes:
    return master_fernet.encrypt(file_key)

def decrypt_file_key_from_db(enc_file_key: bytes) -> bytes:
    return master_fernet.decrypt(enc_file_key)

# -------------------- Routes --------------------
@app.route("/")
def index():
    return render_template("index.html")

# ----------- Register/Login/Logout -------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))
        pw_hash = generate_password_hash(password)
        # Make first registered user an admin for convenience (optional)
        is_admin = (User.query.count() == 0)
        user = User(username=username, password_hash=pw_hash, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash("Registered. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# ----------- Dashboard & Upload -------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Files the current user owns or are shared with them
    owned_files = File.query.filter_by(owner_id=current_user.id).order_by(File.uploaded_at.desc()).all()
    shared_entries = FileKey.query.filter_by(user_id=current_user.id).all()
    shared_files = [entry.file for entry in shared_entries if entry.file.owner_id != current_user.id]
    return render_template("dashboard.html", owned_files=owned_files, shared_files=shared_files)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            flash("No file provided.", "danger")
            return redirect(request.url)
        original_filename = f.filename
        # generate a random stored filename to avoid collisions
        stored_filename = secrets.token_hex(16)
        file_bytes = f.read()
        # generate per-file key and encrypt file bytes
        file_key = generate_file_key()
        enc_bytes = encrypt_file_bytes(file_bytes, file_key)
        # save encrypted file to disk
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        with open(path, "wb") as fh:
            fh.write(enc_bytes)
        # add file metadata to DB
        file_row = File(
            original_filename=original_filename,
            stored_filename=stored_filename,
            owner_id=current_user.id
        )
        db.session.add(file_row)
        db.session.commit()
        # store encrypted file key in DB for owner (encrypted with server MASTER_KEY)
        enc_file_key = encrypt_file_key_for_db(file_key)
        file_key_row = FileKey(file_id=file_row.id, user_id=current_user.id, enc_file_key=enc_file_key)
        db.session.add(file_key_row)
        db.session.commit()
        flash("File uploaded and encrypted successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

# ----------- Share file -------------
@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    file_row = File.query.get_or_404(file_id)
    if file_row.owner_id != current_user.id:
        flash("Only the owner can share this file.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username").strip()
        if not username:
            flash("Enter username to share with.", "danger")
            return redirect(request.url)
        recipient = User.query.filter_by(username=username).first()
        if not recipient:
            flash("No such user.", "danger")
            return redirect(request.url)
        # If already shared with that user, do nothing
        existing = FileKey.query.filter_by(file_id=file_id, user_id=recipient.id).first()
        if existing:
            flash("Already shared with that user.", "info")
            return redirect(url_for("dashboard"))
        # Get the stored encrypted file key for the owner
        owner_fk = FileKey.query.filter_by(file_id=file_id, user_id=current_user.id).first()
        if not owner_fk:
            flash("File key missing for owner (unexpected).", "danger")
            return redirect(url_for("dashboard"))
        # For simplicity in this course project we store per-user access by duplicating the
        # encrypted file key entry so the recipient can decrypt it via server master key.
        # (In production you'd use per-user key wrapping.)
        new_fk = FileKey(file_id=file_id, user_id=recipient.id, enc_file_key=owner_fk.enc_file_key)
        db.session.add(new_fk)
        db.session.commit()
        flash(f"Shared with {recipient.username}.", "success")
        return redirect(url_for("dashboard"))
    return render_template("file_view.html", file=file_row)

# ----------- Download file -------------
@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file_row = File.query.get_or_404(file_id)
    # Admins may view metadata but are not allowed to download files
    if current_user.is_admin and current_user.id != file_row.owner_id:
        flash("Admin is not allowed to download files.", "warning")
        return redirect(url_for("dashboard"))
    # check user has a FileKey entry for this file
    fk = FileKey.query.filter_by(file_id=file_id, user_id=current_user.id).first()
    if not fk:
        flash("You do not have access to this file.", "danger")
        return redirect(url_for("dashboard"))
    # decrypt stored file key
    try:
        file_key = decrypt_file_key_from_db(fk.enc_file_key)
    except Exception as e:
        flash("Failed to decrypt file key.", "danger")
        return redirect(url_for("dashboard"))
    # read encrypted bytes from disk, decrypt and send as attachment
    path = os.path.join(app.config['UPLOAD_FOLDER'], file_row.stored_filename)
    if not os.path.exists(path):
        flash("File missing on server.", "danger")
        return redirect(url_for("dashboard"))
    with open(path, "rb") as fh:
        enc_bytes = fh.read()
    try:
        dec_bytes = decrypt_file_bytes(enc_bytes, file_key)
    except Exception as e:
        flash("Failed to decrypt file contents.", "danger")
        return redirect(url_for("dashboard"))
    # send file bytes as attachment
    return (dec_bytes, 200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": f'attachment; filename="{file_row.original_filename}"'
    })

# ----------- Delete file -------------
@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    file_row = File.query.get_or_404(file_id)
    # only owner or admin (admin cannot download but can delete) can delete
    if current_user.id != file_row.owner_id and not current_user.is_admin:
        flash("You are not allowed to delete this file.", "danger")
        return redirect(url_for("dashboard"))
    # remove file from disk
    path = os.path.join(app.config['UPLOAD_FOLDER'], file_row.stored_filename)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        # continue to remove DB entries even if file deletion fails
        pass
    # deleting File will cascade delete FileKey entries
    db.session.delete(file_row)
    db.session.commit()
    flash("File deleted.", "info")
    return redirect(url_for("dashboard"))

# ----------- Admin view -------------
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    files = File.query.order_by(File.uploaded_at.desc()).all()
    # Admin sees metadata but we do not show download links for admin
    return render_template("admin.html", files=files)

# ----------- Utility: view file metadata -------------
@app.route("/file/<int:file_id>")
@login_required
def file_view(file_id):
    file_row = File.query.get_or_404(file_id)
    # only owner, admin, or user with FileKey can view metadata
    fk = FileKey.query.filter_by(file_id=file_id, user_id=current_user.id).first()
    if current_user.id != file_row.owner_id and not current_user.is_admin and not fk:
        flash("You are not allowed to view this file.", "danger")
        return redirect(url_for("dashboard"))
    shared_with = [fk.user.username for fk in file_row.file_keys]
    return render_template("file_view.html", file=file_row, shared_with=shared_with)

# -------------------- Initialize DB --------------------
@app.before_request
def initialize_once():
    if not hasattr(app, 'initialized'):
        # whatever code was inside initialize()
        app.initialized = True


# -------------------- Run --------------------
if __name__ == "__main__":
    app.run(debug=True)
