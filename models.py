from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt #proven, fast
from sqlalchemy import JSON

from datetime import datetime, timezone, timedelta

#using authenticator apps:
from totp import make_random_secret, verify_totp



db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    #fav_color = db.Column(db.String(50), nullable=False)
    fav_images = db.Column(db.String(200)) 
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_disabled = db.Column(db.Boolean, default=False)

    # TOTP fields for authenticator apps
    totp_secret = db.Column(db.String(32), nullable=True)  # Base32 secret
    totp_enabled = db.Column(db.Boolean, default=False)

    #os_name = db.Column(db.String(50), nullable=True)
    #ip_address = db.Column(db.String(50), nullable=True)
    
    # Relationship to devices
    devices = db.relationship("Device", backref="user", lazy=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    def set_fav_images(self, images_list):
        combined = ",".join(sorted(images_list))  # order does nnot matter (sorted - c,d,e), convert list to string "mon, cat", only works with string/bytes
        self.fav_images = bcrypt.generate_password_hash(combined).decode("utf-8")

    def check_fav_images(self, images_list):
        #Verify emojis against stored hash
        combined = ",".join(sorted(images_list))
        return bcrypt.check_password_hash(self.fav_images, combined)
    
    
    # TOTP methods
    def generate_totp_secret(self):
        #Make a random secret
        self.totp_secret = make_random_secret()
        return self.totp_secret
    
    def get_totp_uri(self):
        #Make the authenticator app URI
        if not self.totp_secret:
            return None
        return f"otpauth://totp/SecureAccess:{self.email}?secret={self.totp_secret}&issuer=SecureAccess"
    
    def verify_totp(self, token):
        #Check if the code is correct
        if not self.totp_secret:
            return False
        return verify_totp(self.totp_secret, token)
    

import hashlib
class Device(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    os_name = db.Column(db.String(50), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)

    #adding this broser info things to make fingerprint more specific but not exactly - MAC address cannot be gotten from web browser, protected (sandoboxed) as is considered PII BY gdPR
    user_agent = db.Column(db.String(200), nullable=True)   
    screen_res = db.Column(db.String(20), nullable=True)   

    timezone = db.Column(db.String(50), nullable=True)
    hardware_cores = db.Column(db.String(10), nullable=True)
    device_memory = db.Column(db.String(10), nullable=True)

    fingerprint_hash = db.Column(db.String(64), nullable=True)  
    created_at = db.Column(db.DateTime, default=lambda: datetime.now()) #this is not correctly worknig - 2hrs behind, i don't know why

    def set_fingerprint(self):
        raw = f"{self.os_name}-{self.device_type}-{self.user_agent}-{self.screen_res}-{self.timezone}-{self.hardware_cores}-{self.device_memory}"
        self.fingerprint_hash = hashlib.sha256(raw.encode()).hexdigest()

class PersistentToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now())
    expires_at = db.Column(db.DateTime, nullable=False)
    user = db.relationship("User", backref="tokens")


#we are tyring to make the time factor-specific to each user, learn the behaviour, the last 70% of logins time
class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)


class TrustConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    factor_name = db.Column(db.String(50), unique=True, nullable=False)
    weight = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(), onupdate=datetime.now())

    @staticmethod
    def get_weights():
        defaults = {
            "known_device": 3,
            "trusted_subnet": 5,
            "safe_login_time": 1,
            "persistent_token": 5,
            "medium_access_threshold": 9,
            "high_access_threshold": 13
        }
        #get all things by admin from db
        configs = TrustConfig.query.all()
        if not configs:
            return defaults
        dynamic = {c.factor_name: c.weight for c in configs} #convert found records to dict to then be merge with default
        return {**defaults, **dynamic}


class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now())

    user = db.relationship("User", backref="security_logs", lazy=True)




