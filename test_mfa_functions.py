from auth import AuthManager
import pyotp

def test_mfa_functions():
    auth = AuthManager()
    username = f'test_mfa_user_{int(time.time())}'
    password = 'password123'
    new_password = 'new_password123'
    
    print("\n=== MFA Function Test Started ===")
    print(f"Using username: {username}")
    
    # 1. Register new user
    print('\n1. Registering new user...')
    register_result = auth.register(username, password)
    print('Register:', register_result)
    if not register_result:
        print("Registration failed: Username may already exist, please try another username")
        return
    
    # 2. Check MFA status (should be disabled)
    print('\n2. Checking initial MFA status...')
    mfa_status = auth.is_mfa_enabled(username)
    print('MFA status:', 'Enabled' if mfa_status else 'Disabled')
    
    # 3. Enable MFA
    print('\n3. Enabling MFA...')
    secret = auth.enable_mfa(username)
    print('MFA secret:', secret)
    
    # 4. Check MFA status again (should be enabled)
    print('\n4. Checking MFA status...')
    mfa_status = auth.is_mfa_enabled(username)
    print('MFA status:', 'Enabled' if mfa_status else 'Disabled')
    
    # 5. Get current verification code
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    print(f'Current verification code: {current_code}')
    
    # 6. Disable MFA
    print('\n5. Disabling MFA...')
    disable_result = auth.disable_mfa(username, current_code)
    print('Disable result:', disable_result)
    
    # 7. Check MFA status again (should be disabled)
    print('\n6. Checking MFA status...')
    mfa_status = auth.is_mfa_enabled(username)
    print('MFA status:', 'Enabled' if mfa_status else 'Disabled')
    
    # 8. Reset password
    print('\n7. Resetting password...')
    reset_result = auth.reset_password(username, password, new_password)
    print('Reset result:', reset_result)
    
    # 9. Login with new password
    print('\n8. Logging in with new password...')
    login_result = auth.login(username, new_password)
    print('Login result:', login_result)
    
    print("\n=== Test Completed ===")
    if all([register_result, disable_result, reset_result, login_result['status'] == 'success']):
        print("All functionality tests passed successfully!")
    else:
        print("Some functionality tests failed, please check the output information.")

if __name__ == '__main__':
    import time
    test_mfa_functions() 