# adaptive-mfa-trust-system
Python/Flask-based adaptive MFA system with trust scoring, device tracking, and rule-based authentication decisions.

# Overview

This project implements a dynamic Multi-Factor Authentication (MFA) system that adjusts authentication requirements based on user trust level, device information, and login behaviour.

The goal is to reduce unnecessary MFA prompts while maintaining strong security.

# Features
User authentication system (login/register)
Device recognition and tracking
Login history analysis
Trust scoring system
Adaptive MFA decision engine
Rule-based risk evaluation

# How It Works
1. User attempts login
2. System evaluates:
 - Device familiarity
 - Login location
 - Login history
3. Trust score is calculated
4. System decides:
 - Allow access to which Level of access
 - Require MFA to verify further

# Tech Stack
- Python
- Flask
- SQLAlchemy
- SQLite
