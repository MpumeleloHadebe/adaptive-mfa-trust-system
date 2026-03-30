from datetime import datetime # 3rd factor chacking unnormal hrs
import hashlib
from flask import request
from models import db, PersistentToken, LoginHistory, TrustConfig, SecurityLog


class TrustEngine:
    def calculate_trust_score(self, user, device):
        score = 0
        reasons = []

        #current_device_info = device.get_info()
        current_ip = device.ip_address or ""
        current_os = device.os_name or ""
        current_type = device.device_type or ""

        user_agent = device.user_agent or ""
        screen_res = device.screen_res or ""

        timezone = device.timezone or ""
        hardware_cores = device.hardware_cores or ""
        device_memory = device.device_memory or ""

        #current_fingerprint = f"{current_ip}-{current_os}-{current_type}"
        # Calc hash for current device
        raw = f"{current_os}-{current_type}-{user_agent}-{screen_res}-{timezone}-{hardware_cores}-{device_memory}"
        current_hash = hashlib.sha256(raw.encode()).hexdigest()

       
        # all weight are specified by the admin, not default - ZT, after admin checks logs and see attack they adjust weights and thresholds
        weights = TrustConfig.get_weights()

        #check known device - so check if any devices matches the current fingerprint
        known = False
        for d in user.devices:
            try:
                if d.fingerprint_hash == current_hash:
                    known = True
                    break
            except Exception:
                continue

        if known:
            score += weights["known_device"]
            reasons.append(f"Known device (+{weights['known_device']})")
        else:
            reasons.append("Unknown device (+0)")


        # --- Check trusted subnet for each user-specific to that users
        is_subnet_trusted = False
        for known_device in user.devices:
            known_ip = known_device.ip_address or ""
            if known_ip and current_ip.startswith(self._get_subnet_prefix(known_ip)):
                is_subnet_trusted = True
                break

        if is_subnet_trusted:
            score += weights["trusted_subnet"]
            reasons.append(f"Trusted subnet (+{weights['trusted_subnet']})")
        else:
            reasons.append("Untrusted subnet (+0)")


        # User-specific safe time (learned)
        if self.is_safe_login_time(user):
            score += weights["safe_login_time"]
            reasons.append(f"Safe login time (+{weights['safe_login_time']})")
        else:
            reasons.append("Outside usual hours (+0)")



        # ---------------- Persistent token check ----------------
        persistent_cookie = request.cookies.get("persistent_token")
        if persistent_cookie:
            token = PersistentToken.query.filter_by(user_id=user.id, token=persistent_cookie).first()
            if token and token.expires_at > datetime.now():
                score += weights["persistent_token"]
                reasons.append(f"Persistent token recognized (+{weights['persistent_token']})")
            else:
                reasons.append("Persistent token invalid or expired (+0)")
        else:
            reasons.append("No persistent token (+0)")


           
        print(f"[DEBUG] Current IP: {current_ip}")
        print(f"[DEBUG] User devices count: {len(user.devices)}")
        print(f"[DEBUG] Current device hash: {current_hash}")
        for d in user.devices:
            print(f"[DEBUG] Stored device hash: {d.fingerprint_hash}")
        print(f"[DEBUG] Device known: {known}")
        print(f"[DEBUG] Final score: {score}")
        
        #these do no work they will always say the server details and not the details of the client device
        import platform
        system_info = platform.uname()
        print(f"System: {system_info.system}")
        print(f"Node Name: {system_info.node}")
        print(f"Release: {system_info.release}")
        print(f"Version: {system_info.version}")
        print(f"Machine: {system_info.machine}")
        print(f"Processor: {system_info.processor}")

        '''
        These look great, how ever they will not work because they are for wherever the flask code is running so if its on hosting computer it will alywas say Mpumelelo and not the actual device the other peron is using - so .platform is wrong
        System: Windows
        Node Name: Mpumelelo
        Release: 11
        Version: 10.0.26100
        Machine: AMD64
        Processor: AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD
        '''


        # Log the trust calculation - db not defined
        log = SecurityLog(
            user_id=user.id,
            event_type="TRUST_CALCULATION",
            description=f"Trust score: {score}, Factors: {', '.join(reasons)}",
            ip_address=current_ip
        )
        db.session.add(log)
        db.session.commit()

        return score, reasons
    

    def _get_subnet_prefix(self, ip):
        # Extract the first 2 blocks of the IP as subnet (e.g., 192.168.1.35) -> 192, "168", "1","35"
        parts = ip.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3]) + "."
        return ip 
    

    # ---------- leaerning the login time windows ----------
    def learn_login_window(self, user_id, window_size=10, core_fraction=0.7):

        # 1)# Get the last 5 login times for this user, i need to increase this so it include more time cause this will say loggin time is 10:00am - 10:59 am
        recent_logins = (LoginHistory.query
             .filter_by(user_id=user_id)
             .order_by(LoginHistory.login_time.desc())
             .limit(window_size))
        logins = recent_logins.all() #convert to a list [14:00, 13:30, 13:15, 9:00, 9:30, 9:45, 10:00, 14:30, 15:00, 16:00]

            #If no logins at all (first-time user), return 24-hour window
        if not logins:
            print("[DEBUG] No logins found - first time user, using 24-hour window")
            return (0, 23)  # 24-hour access for new users

    #If very few logins, be more permissive
        if len(logins) < 5:
            print(f"[DEBUG] Few logins ({len(logins)}), using permissive window")
        
            # Get all hours from existing logins and expand window
            login_hours = [login.login_time.hour for login in logins]
            start = max(0, min(login_hours) - 2)  # Expand 2 hours before earliest login
            end = min(23, max(login_hours) + 2)   # Expand 2 hours after latest login
            return (start, end)
        
        # 2) counthow dict many logins per hour, how many times have user X loggen in at X hour, like you logged in 5 times at 6pm
        hour_counts = {}
        for login in logins:
            login_hour = login.login_time.hour
            hour_counts[login_hour] = hour_counts.get(login_hour, 0) + 1
            print(f"[DEBUG] Login hours counted: {hour_counts}")

        # Calculate how many logins we need to cover (70% of total)
        total_logins = len(logins) #how many login we have
        target_count = int(total_logins * core_fraction)

        # Sort hours by most frequent first (14, 2), 17,4 = so 17, 4 will be the first and its already more than 70 percent so login would be 17:00 - 17:59
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)

        #pick most common hours until we get our 70 % 
        selected_hours = []
        current_count = 0
        for hour, count in sorted_hours:
                selected_hours.append(hour)
                current_count += count
                if current_count >= target_count:
                    break

        # 4) If the common hours are [9, 10, 11], then your window is 9 AM to 11 PM
        start = min(selected_hours)
        end   = max(selected_hours)
        print(f"[DEBUG] Learned window → {start}:00 to {end}:59")
        return (start, end)

    def is_safe_login_time(self, user):
        current_hour= datetime.now().hour
        safe_start, safe_end = self.learn_login_window(user.id)

        # Check if current hour is within safe window
        if safe_start <= safe_end:
            is_safe = safe_start <= current_hour <= safe_end
        else:
            # Overnight window (e.g., 10 PM to 2 AM)
            is_safe = current_hour >= safe_start or current_hour <= safe_end
        return is_safe
        
    #return user.preferred_login_start <= current_time <= user.preferred_login_end



#-----------------------------mfa engine-------------------
# responsiblw for the mfa challenge 
import random,smtplib,ssl
import pyotp
from datetime import datetime

class MFAEngine:
    def ask_question(self, user, trust_score):
        
        weights = TrustConfig.get_weights()
        high_threshold = weights["high_access_threshold"]
        medium_threshold = weights["medium_access_threshold"]

        # Check if admin has TOTP enabled
        #if user.is_admin and user.totp_enabled:
        #   return {"type": "totp", "message": "Enter code from authenticator app"}

         # If user has TOTP enabled, use authenticator app
        #if user.totp_enabled:
         #   return {"type": "totp", "message": "Enter code from authenticator app"}
        
        if trust_score >= high_threshold:
            #return {"type": "color"}
            #easier mfa - you do not need to log into your email or even have your phone with you, or even to look at it
            return {"type": "image", "fav_images": user.fav_images}
        
        elif trust_score >= medium_threshold:
            #harder - mfa needs to log into email
            if user.totp_enabled:
                return {"type": "totp", "message": "Enter code from authenticator app"}
            else:
                otp = self.genearte_otp()
                self.send_email(user.email,otp)
                return {"type": "otp", "otp": otp}
        else:
            return {"type": "deny"}
        
    def genearte_otp(self):
        return str(random.randint(100000, 999999))
    
    def send_email(self, receiving_email, otp):
        system_email = "trevorfloch@gmail.com" #sender email
        sender_password = "bcqaufrwobrbikke" #it is wrong to do tjis here but it works 

        message = f"Subject: Yor Secure Access OTP\n\nYour one-time password is: {otp}. If you didn't request this, please ignore."

        context = ssl.create_default_context()

        try:
            server = smtplib.SMTP("smtp.gmail.com",587)
            with server:
                server.starttls(context=context)
                server.login(system_email, sender_password)
                server.sendmail(system_email,receiving_email,message)
                print(f"[Debug] sent otp to {receiving_email}")
        except Exception as e:
            print(f"Error Failed to send otp: {e}")