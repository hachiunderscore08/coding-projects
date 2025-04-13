import pyotp
import time

class MFAManager:
    def __init__(self, user_id):
        self.user_id = user_id
        self.secret = pyotp.random_base32()
        print(f"Generated secret: {self.secret}")  # debug information

    def get_provisioning_uri(self, username):
        """Generate the provisioning URI"""
        totp = pyotp.TOTP(self.secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name="SecureStorageApp"
        )
        print(f"Generated URI: {uri}")  # debug information
        return uri
    
    
    def verify_totp(self, code):
        totp = pyotp.TOTP(self.secret)
        return totp.verify(code)