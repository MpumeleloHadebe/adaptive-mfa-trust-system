from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    #fav_color = StringField("Favourite Color", validators=[DataRequired(), Length(min=2, max=50)])
    

    fav_images = SelectMultipleField("Pick 2 Favorite Images (Used for MFA)", choices=[
        ("cat", "🐱 Cat"),
        ("dog", "🐶 Dog"),
        ("car", "🚗 Car"),
        ("tree", "🌳 Tree"),
        ("sun", "☀️ Sun"),
        ("moon", "🌙 Moon"),
        ("star", "⭐ Star"),
        ("book", "📚 Book"),
        ("music", "🎵 Music"),
        ("pizza", "🍕 Pizza"),
        ("football", "⚽ Football"),
        ("flower", "🌸 Flower")
    ], validators=[DataRequired(),Length(min=2, max=2, message='Please select only 2 images.')])
    
    
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class TOTPSetupForm(FlaskForm):
    enable_2fa = BooleanField("Enable Two-Factor Authentication")
    submit = SubmitField("Save Settings")

class UserTOTPSetupForm(FlaskForm):
    enable_2fa = BooleanField("Enable Authenticator App") #checkbox
    submit = SubmitField("Save Settings")

class TOTPVerifyForm(FlaskForm):
    totp_code = StringField("Authenticator Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")