import os, time, binascii, hashlib, hmac, traceback, requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from security_module import attach_security
from vuln_scan import scan_site

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ok')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mabi.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    app.logger.error(f"Exception: {e}\n{tb}")
    if isinstance(e, HTTPException):
        return e
    return jsonify({"error": "Une erreur serveur est survenue."}), 500

db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    api_key_hash = db.Column(db.String(64), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)
    def generate_api_key(self):
        key = binascii.hexlify(os.urandom(24)).decode()
        self.api_key_hash = hashlib.sha256(key.encode()).hexdigest()
        db.session.commit()
        return key
    def check_api_key(self, key):
        if not self.api_key_hash:
            return False
        return hmac.compare_digest(self.api_key_hash, hashlib.sha256(key.encode()).hexdigest())

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

VT_API_KEY = os.getenv('VT_API_KEY', 'e337abac5c0db3a50ee6fe5f485253e943cfaf4a7b80ccdfff2867edd0974df1')

def verifier_url(url):
    if not url:
        return {"status": "error", "message": "URL vide."}
    if not url.startswith(('http://','https://')):
        url = 'http://' + url.strip()
    headers = {'x-apikey': VT_API_KEY}
    resp = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
    if resp.status_code != 200:
        return {"status": "error", "message": f"Erreur VirusTotal ({resp.status_code})"}
    url_id = resp.json()['data']['id']
    for _ in range(15):
        r2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
        if r2.status_code != 200:
            return {"status": "error", "message": f"Erreur VirusTotal ({r2.status_code})"}
        data = r2.json()['data']['attributes']
        if data['status'] == 'completed':
            m = data['stats'].get('malicious', 0)
            return {
                "status": "danger" if m > 0 else "safe",
                "message": f"🚨 Attention! Ce lien est détecté malveillant par {m} antivirus ⚠️" if m > 0 else "✅ Ce lien semble sécurisé."
            }
        time.sleep(1)
    return {"status":"waiting","message":"⏳ Analyse en cours, patientez…"}

@app.route('/', methods=['GET','POST'])
@login_required
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            flash("Merci de saisir une URL.", "warning")
            return redirect(url_for('home'))
        result = verifier_url(url)
        history = ScanHistory(user_id=current_user.id, scan_type='link', target=url, result=result['message'], status=result['status'])
        db.session.add(history); db.session.commit()
    return render_template('home.html', result=result)

@app.route('/vulnscan', methods=['GET','POST'])
@login_required
def vulnscan():
    context = None
    if request.method == 'POST':
        site = request.form.get('site_url')
        if not site:
            flash("Merci de saisir un URL de site.", "warning")
            return redirect(url_for('vulnscan'))

        report = scan_site(site)
        vuln_count = report.get('vuln_count', 0)

        if vuln_count >= 3:
            conclusion = "❗️ Plusieurs vulnérabilités détectées..."
            status = "danger"
        elif vuln_count > 0:
            conclusion = "⚠️ Quelques vulnérabilités détectées..."
            status = "warning"
        else:
            conclusion = "✅ Votre site semble très bien sécurisé ! 🎉"
            status = "safe"

        context = {
            "headers": report.get('headers_status', ''),
            "subdomains": report.get('subdomain_status', ''),
            "sensitive": report.get('sensitive_status', ''),
            "sql": report.get('sql_injection_status', ''),
            "ports": report.get('open_ports_status', ''),
            "conclusion": report.get('conclusion', conclusion),
            "status": status
        }

        history = ScanHistory(
            user_id=current_user.id,
            scan_type='site',
            target=site,
            result=conclusion,
            status=status
        )
        db.session.add(history)
        db.session.commit()

    return render_template('vulnscan.html', results=context)

@app.route('/history')
@login_required
def history():
    histories = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', histories=histories)
@app.route('/export-history', methods=['POST'])
@login_required
def export_history():
    from io import StringIO
    import csv

    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Type', 'Cible', 'Résultat', 'Statut', 'Date'])

    for s in scans:
        writer.writerow([
            s.scan_type,
            s.target,
            s.result,
            s.status,
            s.timestamp.strftime("%d/%m/%Y %H:%M")
        ])

    output = si.getvalue().encode('utf-8')

    return (
        output,
        200,
        {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="historique_scans.csv"'
        }
    )



@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(email=form.email.data).first()
        if u and u.check_password(form.password.data):
            login_user(u); flash("Connexion réussie !","success"); return redirect(url_for('home'))
        flash("Email ou mot de passe invalide.","danger")
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email déjà utilisé.","warning"); return redirect(url_for('signup'))
        u=User(email=form.email.data); u.set_password(form.password.data)
        db.session.add(u); db.session.commit()
        flash("Inscription réussie.","success"); return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash("Déconnexion réussie.","info"); return redirect(url_for('login'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

attach_security(app)

if __name__ == '__main__':
    app.run(debug=True)