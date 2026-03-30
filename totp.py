import struct, hashlib, hmac, time, base64, os

def generate_one_time_password(key, counter):
    # generate otp
    data = struct.pack('>Q', int(counter))
    hmac_hash = hmac.HMAC(key, data, digestmod=hashlib.sha1).digest()

    offset = hmac_hash[len(hmac_hash) - 1] & 0x0f
    otp = (hmac_hash[offset] & 0x7f) << 24 \
         | (hmac_hash[1 + offset] & 0xff) << 16 \
         | (hmac_hash[2 + offset] & 0xff) << 8 \
         | (hmac_hash[3 + offset] & 0xff)
    return otp % 1_000_000

def make_random_secret():
    """Make random base32 secret"""
    random_bytes = os.urandom(20)
    return base64.b32encode(random_bytes).decode('utf-8').replace('=', '')

def verify_totp(secret, user_code):
    #Verify TOTP code with clock drift tolerance
    secret_bytes = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
    
    # Check current time and interval (90-second window)
    current_interval = int(time.time() // 30)
    
    for i in range(-1, 2):  # Check -1, 0, +1 intervals
        correct_code = generate_one_time_password(secret_bytes, current_interval + i)
        if user_code == str(correct_code).zfill(6):
            return True
    
    return False
