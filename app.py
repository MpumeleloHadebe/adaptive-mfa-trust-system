from flask import Flask, render_template, redirect, url_for, flash, request, session, make_response, jsonify
from models import db, bcrypt, User, Device, PersistentToken, LoginHistory, TrustConfig, SecurityLog
from forms import RegistrationForm, LoginForm, TOTPVerifyForm, TOTPSetupForm
from authentication_engines import TrustEngine, MFAEngine
import os
import binascii
from datetime import timedelta, datetime
from functools import wraps

import qrcode
import base64
from io import BytesIO

app = Flask(__name__)
app.config["SECRET_KEY"] = "devkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt.init_app(app)

trust_engine = TrustEngine()
mfa_engine = MFAEngine()

def admin_required(f):
    @wraps(f)
    def check_admin(*args, **kwargs):  # Add arguments
        user_id = session.get("user_id")
        if not user_id:
            flash("Please log in first.", "warning") 
            return redirect(url_for("login"))
        
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("low_access"))
        
        return f(*args, **kwargs)  #run original fn and pass arguments
    return check_admin


@app.route("/")
def home():
    return render_template("home.html")

@app.route("/users")
def users():
    all_users = User.query.all()
    return render_template("users.html", users=all_users)

def get_os_from_user_agent(user_agent):
    ua = user_agent.lower()
    if "windows" in ua:
        return "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        return "MacOS"
    elif "linux" in ua:
        return "Linux"
    elif "android" in ua:
        return "Android"
    elif "iphone" in ua or "ios" in ua:
        return "iOS"
    else:
        return "Unknown"

def get_device_info():
    ip = request.remote_addr or "unknown"
    user_agent = request.user_agent.string or "unknown"
    os_name = get_os_from_user_agent(user_agent)

    # Get screen dimensions and additional fingerprint data
    screen_width = request.form.get("screen_width", type=int) or 0
    screen_height = request.form.get("screen_height", type=int) or 0
    timezone = request.form.get("timezone_name", "")
    hardware_cores = request.form.get("hardware_cores", "")
    device_memory = request.form.get("device_memory", "")

    if screen_width > 1000:
        device_type = "laptop"
    elif screen_width > 0:
        device_type = "mobile"
    else:
        device_type = "unknown"

    screen_res = f"{screen_width}x{screen_height}" if screen_width and screen_height else "unknown"

    print(f"[DEBUG] more device info: {device_type}, {screen_res}, Timezone: {timezone}, Cores: {hardware_cores}, RAM: {device_memory}")
    return ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():  #g f skip 
        email = form.email.data.strip().lower()
        password = form.password.data.strip()

        if User.query.filter_by(email=email).first():
            flash("Email is already registered. Please log in.", "danger")
            return redirect(url_for("login"))

        new_user = User(email=email)
        if User.query.count() == 0:
            new_user.is_admin = True
            flash("First user registered as administrator.", "success")
        
        new_user.set_password(password)
        new_user.set_fav_images(form.fav_images.data)
        db.session.add(new_user)
        db.session.commit()

        # Create device with enhanced fingerprint
        ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()

        new_device = Device(
            user_id=new_user.id, 
            ip_address=ip, 
            os_name=os_name, 
            device_type=device_type,
            user_agent=user_agent,
            screen_res=screen_res,
            timezone=timezone,
            hardware_cores=hardware_cores,
            device_memory=device_memory
        )
        new_device.set_fingerprint()
        db.session.add(new_device)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Check if user exists and is not disabled
        if user and user.is_disabled:
            flash("This account has been disabled. Please contact an administrator.", "danger")
            return render_template("login.html", form=form)
        #user taht are not disabled
        if user and user.check_password(form.password.data):
            
            # If admin with 2FA enabled, go to TOTP verification
            if user.is_admin and user.totp_enabled:
                session["pending_admin_id"] = user.id
                session["pending_admin_login"] = True
                
                log = SecurityLog(
                    user_id=user.id,
                    event_type="ADMIN_2FA_REQUIRED",
                    description="Admin login requires TOTP verification",
                    ip_address=request.remote_addr
                )
                db.session.add(log)
                db.session.commit()
                return redirect(url_for("user_2fa_verify"))
            
            #for non admin and admin who did not set up the totp
            session["user_id"] = user.id
            flash("Login successful!", "success")

            log = SecurityLog(
                user_id=user.id,
                event_type="LOGIN_SUCCESS",
                description="User logged in successfully",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()

            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("low_access"))
        else:
            is_suspicious = check_suspicious_activity(request.remote_addr, form.email.data)
            
            #LOG FAILED LOGIN ATTEMPTS
            log = SecurityLog(
                user_id=None,
                event_type="LOGIN_FAILED",
                description=f"Failed login attempt for email: {form.email.data}",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()

            if is_suspicious:
                flash("Multiple failed attempts detected from your IP. Please try again later.", "danger")
            else:
                flash("Login failed. Check your email and password.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/low")
def low_access():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    return render_template("low_access.html", user=user)

@app.route("/medium_access")
def medium_access():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    
    # For admins, redirect to admin dashboard
    if user.is_admin:
        return redirect(url_for("admin_dashboard"))
    
    # For regular users, show medium access page
    return render_template("medium_access.html", user=user)


#----------------------------request higher levels of access ---------------------------
@app.route("/request_medium", methods=["POST"])
def request_medium():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()
    
    # Create temporary device for trust calculation - thsi deviec is compared to the stored, if there is 
    temp_device = Device(
        ip_address=ip, os_name=os_name, device_type=device_type,
        user_agent=user_agent, screen_res=screen_res,
        timezone=timezone, hardware_cores=hardware_cores, device_memory=device_memory
    )
    temp_device.set_fingerprint()

    score, reasons = trust_engine.calculate_trust_score(user, temp_device)
    weights = TrustConfig.get_weights()
    medium_threshold = weights["medium_access_threshold"]

    if score >= medium_threshold:
        _log_login(user.id)
        log = SecurityLog(
            user_id=user.id,
            event_type="ACCESS_GRANTED_MEDIUM",
            description=f"Medium access granted - Trust score: {score}/{medium_threshold}",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()

        flash(f"Medium Access Granted. Trust Score: {score}/{medium_threshold}", "success")
        return render_template("medium_access.html", user=user, score=score, reasons=reasons)
    else:
        log = SecurityLog(
            user_id=user.id,
            event_type="ACCESS_DENIED_MEDIUM",
            description=f"Medium access denied - Trust score: {score}/{medium_threshold}",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()

        return render_template(
            "low_access.html",
            user=user,
            medium_denied=True,
            score=score,
            reasons=reasons,
            required_score=medium_threshold
        )


@app.route("/request_high", methods=["POST"])
def request_high():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()
    
    temp_device = Device(
        ip_address=ip, os_name=os_name, device_type=device_type,
        user_agent=user_agent, screen_res=screen_res,
        timezone=timezone, hardware_cores=hardware_cores, device_memory=device_memory
    )
    temp_device.set_fingerprint()

    score, reasons = trust_engine.calculate_trust_score(user, temp_device)
    
    weights = TrustConfig.get_weights()
    high_threshold = weights["high_access_threshold"]
    medium_threshold = weights["medium_access_threshold"]

    if score < medium_threshold: #to get high access score should be greater or equal to 9
        log = SecurityLog(
            user_id=user.id,
            event_type="ACCESS_DENIED_HIGH",
            description=f"High access denied - Trust score: {score}/{high_threshold}",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()
        flash(f"High Access Denied. Low trust score ({score}/{high_threshold}).", "danger")
        return redirect(url_for("low_access"))
    
    #if the trsut score is good enough, mfa is initiated - each mfa will 
    # depend on the trust score but it must be greater than 9, so for all point since we few factors (14/14) gives image 

    log = SecurityLog(
        user_id=user.id,
        event_type="MFA_CHALLENGE_INITIATED",
        description=f"High access MFA challenge - Trust score: {score}/{high_threshold}",
        ip_address=ip
    )
    db.session.add(log)
    db.session.commit()

    challenge = mfa_engine.ask_question(user, score)

    if challenge["type"] == "totp":
    # TOTP challenge for users with authenticator app enabled
        log = SecurityLog(
            user_id=user.id,
            event_type="MFA_TOTP_SENT",
            description="TOTP challenge presented to user",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()
        return render_template("totp_challenge.html", user=user, score=score, reasons=reasons)
    

    if challenge["type"] == "image":
        log = SecurityLog(
                user_id=user.id,
                event_type="MFA_IMAGE_SENT",
                description="Image-based MFA challenge presented to user",
                ip_address=ip
            )
        db.session.add(log)
        db.session.commit()
    
        options = [
            ("cat", "🐱"),("dog", "🐶"),("car", "🚗"),("tree", "🌳"),
            ("sun", "☀️"),("moon", "🌙"),("star", "⭐"),("book", "📚"),
            ("music", "🎵"),("pizza", "🍕"),("football", "⚽"),("flower", "🌸")
        ]
        import random
        random.shuffle(options)
        return render_template("image_challenge.html", user=user, score=score, reasons=reasons, options=options)
    
    elif challenge["type"] == "otp":
        log = SecurityLog(
            user_id=user.id,
            event_type="MFA_OTP_SENT",
            description="OTP sent to user's email",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()

        session["pending_otp"] = challenge["otp"]
        return render_template("otp_challenge.html", user=user, score=score, reasons=reasons)
    
    elif challenge["type"] == "deny":
        #mfa denied
        log = SecurityLog(
            user_id=user.id,
            event_type="ACCESS_DENIED_HIGH",
            description="MFA engine denied high access request - wrng otp/images",
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()
        flash("Access denied by security system.", "danger")
        return redirect(url_for("low_access"))
    
    flash("Unexpected MFA Failed.", "danger")
    return redirect(url_for("low_access"))


#===========================================MFA Routes ----------------------------------------
@app.route("/verify_otp", methods=["GET","POST"])
def verify_otp():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    
    # Handle GET request - show the OTP form
    if request.method == "GET":
        return render_template("otp_challenge.html", user=user)
    
    # Handle POST request - process the OTP
    entered_otp = (request.form.get("otp") or "").strip()
    expected_otp = session.get("pending_otp")
    if not expected_otp or entered_otp != expected_otp:

        #if otp fail
        log = SecurityLog(
            user_id=user.id,
            event_type="MFA_OTP_FAILED",
            description="Incorrect OTP entered",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        flash("Invalid OTP.", "danger")
        return redirect(url_for("low_access"))

    ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()
    _save_device_if_new(user, ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory)
    session.pop("pending_otp", None)

    log = SecurityLog(
    user_id=user.id,
    event_type="ACCESS_GRANTED_HIGH",
    description="High access granted - MFA verification successful",
    ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

    return _issue_persistent_token(user)

@app.route("/verify_image", methods=["POST"])
def verify_image():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    selected = request.form.getlist("images")

    if not user.check_fav_images(selected):
        log = SecurityLog(
            user_id=user.id,
            event_type="MFA_IMAGE_FAILED", 
            description="Incorrect images selected",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    
        flash("Image check failed.", "danger")
        return redirect(url_for("low_access"))

    ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()
    _save_device_if_new(user, ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory)
    
    log = SecurityLog(
    user_id=user.id,
    event_type="ACCESS_GRANTED_HIGH",
    description="High access granted - MFA verification successful",
    ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

    return _issue_persistent_token(user)
#------------------------------------------------------------------------------------


def _save_device_if_new(user, ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory):
    # Create temp device to calculate fingerprint
    temp_device = Device(
        ip_address=ip, os_name=os_name, device_type=device_type,
        user_agent=user_agent, screen_res=screen_res,
        timezone=timezone, hardware_cores=hardware_cores, device_memory=device_memory
    )
    temp_device.set_fingerprint()
    current_hash = temp_device.fingerprint_hash

    # Check if device already exists
    for d in user.devices:
        if d.fingerprint_hash == current_hash:
            print("[DEBUG] Device already exists, skipping save")
            return

    print(f"[DEBUG] Saving new device with fingerprint")
    new_d = Device(
        user_id=user.id, ip_address=ip, os_name=os_name, 
        device_type=device_type, user_agent=user_agent, 
        screen_res=screen_res, 
        timezone=timezone,hardware_cores=hardware_cores, device_memory=device_memory
    )
    new_d.set_fingerprint()
    db.session.add(new_d)
    db.session.commit()

def _log_login(user_id):
    db.session.add(LoginHistory(user_id=user_id))
    db.session.commit()

def _issue_persistent_token(user):
    persistent_cookie = request.cookies.get("persistent_token")
    existing_token = None

    if persistent_cookie:
        existing_token = PersistentToken.query.filter_by(
            user_id=user.id, token=persistent_cookie
        ).first()

    if existing_token and existing_token.expires_at > datetime.now():
        resp = make_response(render_template("high_access.html", user=user))
        resp.set_cookie("persistent_token", existing_token.token, httponly=True, samesite="Strict")
        return resp

    token_value = binascii.hexlify(os.urandom(16)).decode('utf-8') #converting to hex from bytes
    expires = datetime.now() + timedelta(days=30)

    new_token = PersistentToken(user_id=user.id, token=token_value, expires_at=expires)
    db.session.add(new_token)
    db.session.commit()

    resp = make_response(render_template("high_access.html", user=user))
    resp.set_cookie("persistent_token", token_value, httponly=True, samesite="Strict")
    return resp


#------------------------------ admin -------------------------------------------------

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    log_count = SecurityLog.query.count()
    device_count = Device.query.count()
    current_user = User.query.get(session["user_id"])
    return render_template("admin_dashboard.html", 
                         user_count=user_count, 
                         log_count=log_count,
                         device_count=device_count,
                         current_user=current_user)

@app.route("/admin/config", methods=["GET", "POST"])
@admin_required
def admin_config():
    if request.method == "POST":
        for factor in ["known_device", "trusted_subnet", "safe_login_time", "persistent_token"]:
            weight = int(request.form.get(factor, 0))
            entry = TrustConfig.query.filter_by(factor_name=factor).first()
            if entry:
                entry.weight = weight
            else:
                entry = TrustConfig(factor_name=factor, weight=weight)
                db.session.add(entry)

        for threshold in ["medium_access_threshold", "high_access_threshold"]:
            value = int(request.form.get(threshold, 0))
            entry = TrustConfig.query.filter_by(factor_name=threshold).first()
            if entry:
                entry.weight = value
            else:
                entry = TrustConfig(factor_name=threshold, weight=value)
                db.session.add(entry)
        
        db.session.commit()

        log = SecurityLog(
            user_id=session["user_id"],
            event_type="ADMIN_CONFIG_UPDATE",
            description="Admin updated trust configuration weights and thresholds",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        flash("Configuration updated successfully!", "success")
        return redirect(url_for("admin_config"))

    configs = TrustConfig.get_weights()
    return render_template("admin_config.html", configs=configs)

@app.route("/admin/logs")
@admin_required
def admin_logs():
    #show the last 50 logs, i could show all but it will be too big - check ways to add more but not in one page
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(50).all()
    return render_template("admin_logs.html", logs=logs)

@app.route("/admin/disable_user/<int:user_id>", methods=["POST"])
@admin_required
def disable_user(user_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    current_user = User.query.get(session["user_id"])
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("low_access"))
    
    user_to_disable = User.query.get_or_404(user_id)
    
    # Prevent disabling yourself 
    if user_to_disable.id == current_user.id:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("users"))
    
    user_to_disable.is_disabled = True
    db.session.commit()
    
    # Log the action
    log = SecurityLog(
        user_id=current_user.id,
        event_type="USER_DISABLED",
        description=f"Admin disabled user: {user_to_disable.email}",
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f"User {user_to_disable.email} has been disabled.", "success")
    return redirect(url_for("users"))

@app.route("/admin/enable_user/<int:user_id>", methods=["POST"])
@admin_required
def enable_user(user_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    current_user = User.query.get(session["user_id"])
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("low_access"))
    
    user_to_enable = User.query.get_or_404(user_id)
    user_to_enable.is_disabled = False
    db.session.commit()
    
    # Log the action
    log = SecurityLog(
        user_id=current_user.id,
        event_type="USER_ENABLED",
        description=f"Admin enabled user: {user_to_enable.email}",
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f"User {user_to_enable.email} has been enabled.", "success")
    return redirect(url_for("users"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    current_user = User.query.get(session["user_id"])
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("low_access"))
    
    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself haha
    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users"))
    
    # Delete associated records first before deleting
    Device.query.filter_by(user_id=user_id).delete()
    PersistentToken.query.filter_by(user_id=user_id).delete()
    LoginHistory.query.filter_by(user_id=user_id).delete()
    SecurityLog.query.filter_by(user_id=user_id).delete()
    
    # now delete the user
    db.session.delete(user_to_delete)
    db.session.commit()
    
    flash(f"User {user_to_delete.email} has been deleted successfully.", "success")
    return redirect(url_for("users"))

# --------------------------- 2FA Routes ---------------------------------

def check_suspicious_activity(ip_address, email):
    #Check for multiple failed login attempts from same IP, just for demonstartion, then the adminw ill disable account
    from datetime import datetime, timedelta
    
    # Count failed logins from this IP in last 15 minutes
    recent_failed_logins = SecurityLog.query.filter(
        SecurityLog.event_type == "LOGIN_FAILED",
        SecurityLog.ip_address == ip_address,
        SecurityLog.timestamp > datetime.now() - timedelta(minutes=15)
    ).count()
    
    if recent_failed_logins >= 3:
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_disabled = True  #auto disable
            db.session.commit()

        #log SUSPICIOUS ACTIVITY
        log = SecurityLog(
            user_id=None,
            event_type="SUSPICIOUS_ACTIVITY",
            description=f"Multiple failed login attempts ({recent_failed_logins}) from IP {ip_address} for email: {email}",
            ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
        return True
    return False




#--------------------------authenticator app roues----------
#allows regular users to enable 2fa

@app.route("/2fa/setup", methods=["GET", "POST"])
def user_2fa_setup():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    form = TOTPSetupForm()
    
    if form.validate_on_submit():
        if form.enable_2fa.data and not user.totp_enabled:
            # Generate new secret if not exists
            if not user.totp_secret:
                import pyotp
                user.totp_secret = user.generate_totp_secret()
                db.session.commit()
            
            # Log the action
            log = SecurityLog(
                user_id=user.id,
                event_type="2FA_ENABLED",
                description="User enabled TOTP 2FA",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA enabled! Please scan the QR code with your authenticator app.", "success")
            return redirect(url_for("user_2fa_qr"))
        
        elif not form.enable_2fa.data and user.totp_enabled:
            user.totp_enabled = False
            db.session.commit()
            
            log = SecurityLog(
                user_id=user.id,
                event_type="2FA_DISABLED", 
                description="User disabled TOTP 2FA",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA has been disabled.", "info")
        
        return redirect(url_for("medium_access"))
    
    form.enable_2fa.data = user.totp_enabled
    return render_template("user_2fa_setup.html", form=form, user=user)

@app.route("/2fa/qr", methods=["GET", "POST"])
def user_2fa_qr():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    
    if not user.totp_secret:
        flash("Please enable 2FA first.", "warning")
        return redirect(url_for("user_2fa_setup"))
    
    # Generate QR code
    totp_uri = user.get_totp_uri()
    qr = qrcode.make(totp_uri)
    
    # Convert QR code to base64 for displaying in HTML
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    form = TOTPVerifyForm()

    # Handle verification
    if form.validate_on_submit():
        totp_code = form.totp_code.data.strip()
        
        if user.verify_totp(totp_code):
            user.totp_enabled = True
            db.session.commit()
            
            log = SecurityLog(
                user_id=user.id,
                event_type="2FA_VERIFIED",
                description="User successfully verified TOTP setup",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA setup completed successfully!", "success")
            return redirect(url_for("medium_access"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
    
    return render_template("user_2fa_qr.html", 
                         user=user, 
                         qr_code=qr_base64,
                         secret=user.totp_secret,
                         form=form)

#alllow all to verify totp
@app.route("/2fa/verify", methods=["GET", "POST"])
def user_2fa_verify():
    # Check if this is an admin login requiring TOTP
    if session.get("pending_admin_login") and session.get("pending_admin_id"):
        user = User.query.get(session["pending_admin_id"])
        if not user:
            flash("Invalid session. Please log in again.", "danger")
            return redirect(url_for("login"))
        
        if request.method == "GET":
            # Show TOTP verification form for admin login
            return render_template("totp_challenge.html", user=user, admin_login=True)
        
        totp_code = request.form.get("totp_code", "").strip()
        
        if not totp_code or len(totp_code) != 6:
            flash("Please enter a valid 6-digit code", "danger")
            return render_template("totp_challenge.html", user=user, admin_login=True)
        
        if user.verify_totp(totp_code):
            # Successful admin TOTP verification
            session["user_id"] = user.id
            session.pop("pending_admin_id", None)
            session.pop("pending_admin_login", None)
            
            log = SecurityLog(
                user_id=user.id,
                event_type="ADMIN_LOGIN_SUCCESS",
                description="Admin logged in with TOTP verification",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("Login successful!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            log = SecurityLog(
                user_id=user.id,
                event_type="ADMIN_TOTP_FAILED",
                description="Failed TOTP verification during admin login",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("Invalid authentication code. Please try again.", "danger")
            return render_template("totp_challenge.html", user=user, admin_login=True)
        
    #
    flash("Invalid access. Please log in properly.", "danger")
    return redirect(url_for("login"))



#now handle it during hih access request
@app.route("/verify_totp_challenge", methods=["POST"])
def verify_totp_challenge():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    totp_code = request.form.get("totp_code", "").strip()
    
    if not totp_code or len(totp_code) != 6:
        flash("Please enter a valid 6-digit code.", "danger")
        return render_template("totp_challenge.html", user=user)
    
    if user.verify_totp(totp_code):
        # Successful TOTP verification for high access
        ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory = get_device_info()
        _save_device_if_new(user, ip, os_name, device_type, user_agent, screen_res, timezone, hardware_cores, device_memory)
        
        log = SecurityLog(
            user_id=user.id,
            event_type="ACCESS_GRANTED_HIGH",
            description="High access granted - TOTP verification successful",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        return _issue_persistent_token(user)
    else:
        log = SecurityLog(
            user_id=user.id,
            event_type="MFA_TOTP_FAILED",
            description="Incorrect TOTP code entered for high access",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash("Invalid authentication code. Please try again.", "danger")
        return render_template("totp_challenge.html", user=user)
    

@app.route("/admin/2fa/setup", methods=["GET", "POST"])
@admin_required
def admin_2fa_setup():
    user = User.query.get(session["user_id"])

    form = TOTPSetupForm()
    if form.validate_on_submit():
        if form.enable_2fa.data and not user.totp_enabled:
            # Generate new secret if not exists
            if not user.totp_secret:
                user.generate_totp_secret()
                db.session.commit()
            
            # Log the action
            log = SecurityLog(
                user_id=user.id,
                event_type="ADMIN_2FA_ENABLED",
                description="Admin enabled TOTP 2FA",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA enabled! Please scan the QR code with your authenticator app.", "success")
            return redirect(url_for("admin_2fa_qr"))
        
        elif not form.enable_2fa.data and user.totp_enabled:
            user.totp_enabled = False
            db.session.commit()
            
            log = SecurityLog(
                user_id=user.id,
                event_type="ADMIN_2FA_DISABLED", 
                description="Admin disabled TOTP 2FA",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA has been disabled.", "info")
        
        return redirect(url_for("admin_dashboard"))
    
    form.enable_2fa.data = user.totp_enabled
    return render_template("admin_2fa_setup.html", form=form, user=user)

@app.route("/admin/2fa/qr", methods=["GET", "POST"])
@admin_required
def admin_2fa_qr():
    user = User.query.get(session["user_id"])
    
    if not user.totp_secret:
        flash("Please enable 2FA first.", "warning")
        return redirect(url_for("admin_2fa_setup"))
    
    # Generate QR code
    totp_uri = user.get_totp_uri()
    qr = qrcode.make(totp_uri) #"otpauth://totp/SecureAccess:useremail.com?secret=ABC123..."
    
    # Convert QR code to base64 for displaying in HTML
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    form = TOTPVerifyForm()

    # Handle verification
    if form.validate_on_submit():
        totp_code = form.totp_code.data.strip()
        
        if user.verify_totp(totp_code):
            user.totp_enabled = True
            db.session.commit()
            
            log = SecurityLog(
                user_id=user.id,
                event_type="ADMIN_2FA_VERIFIED",
                description="Admin successfully verified TOTP setup",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash("2FA setup completed successfully!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
    
    return render_template("user_2fa_qr.html", 
                         user=user, 
                         qr_code=qr_base64,
                         secret=user.totp_secret,
                         form=form)

@app.route("/request_email_otp_instead")
def request_email_otp_instead():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    
    # Generate and send email OTP
    otp = mfa_engine.genearte_otp()
    mfa_engine.send_email(user.email, otp)
    session["pending_otp"] = otp
    
    log = SecurityLog(
        user_id=user.id,
        event_type="EMAIL_OTP_FALLBACK", 
        description="User chose email OTP instead of TOTP",
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    flash("Verification code sent to your email!", "success")
    return redirect(url_for('verify_otp'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)