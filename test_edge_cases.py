from auth import AuthManager
import pyotp
import time

def test_edge_cases():
    auth = AuthManager()
    username = f'test_edge_user_{int(time.time())}'
    password = 'password123'
    wrong_password = 'wrong_password'
    
    print("\n=== Edge Cases Test Started ===")
    print(f"Using username: {username}")
    
    # 1. Test duplicate registration
    print('\n1. Testing duplicate registration...')
    print('First registration:')
    result1 = auth.register(username, password)
    print('Result:', result1)
    print('Second registration (same username):')
    result2 = auth.register(username, password)
    print('Result:', result2)
    print('Expected result: First success, second failure')
    
    # 2. Test incorrect password reset
    print('\n2. Testing incorrect password reset...')
    print('Reset with wrong old password:')
    wrong_reset = auth.reset_password(username, wrong_password, 'new_password')
    print('Result:', wrong_reset)
    print('Reset with correct old password:')
    correct_reset = auth.reset_password(username, password, 'new_password')
    print('Result:', correct_reset)
    print('Expected result: Wrong password reset fails, correct password reset succeeds')
    
    # 3. Test MFA verification code error
    print('\n3. Testing MFA verification code error...')
    print('Enable MFA:')
    secret = auth.enable_mfa(username)
    print('MFA secret:', secret)
    
    # Get correct verification code
    totp = pyotp.TOTP(secret)
    correct_code = totp.now()
    wrong_code = '000000'  # Wrong verification code
    
    print('Disable MFA with wrong code:')
    wrong_disable = auth.disable_mfa(username, wrong_code)
    print('Result:', wrong_disable)
    print('Disable MFA with correct code:')
    correct_disable = auth.disable_mfa(username, correct_code)
    print('Result:', correct_disable)
    print('Expected result: Wrong code disable fails, correct code disable succeeds')
    
    # 4. Test multiple login attempts
    print('\n4. Testing multiple login attempts...')
    print('Login with wrong password:')
    wrong_login = auth.login(username, wrong_password)
    print('Result:', wrong_login)
    print('Login with correct password:')
    correct_login = auth.login(username, 'new_password')
    print('Result:', correct_login)
    print('Expected result: Wrong password login fails, correct password login succeeds')
    
    # 5. Test MFA verification code expiration
    print('\n5. Testing MFA verification code expiration...')
    print('Enable MFA:')
    secret = auth.enable_mfa(username)
    print('MFA secret:', secret)
    
    # Get current verification code
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    print('Current verification code:', current_code)
    print('Code generation time:', time.time())
    
    # Verify current code immediately
    print('Verify current code immediately:')
    immediate_verify = auth.verify_mfa(username, current_code)
    print('Result:', immediate_verify)
    print('Expected result: Current code should verify successfully')
    
    # Wait for code expiration (31 seconds)
    print('Waiting for code expiration (31 seconds)...')
    time.sleep(31)
    
    # Verify with expired code
    print('Verify with expired code:')
    expired_verify = auth.verify_mfa(username, current_code)
    print('Result:', expired_verify)
    print('Expired code verification time:', time.time())
    
    # Get new verification code
    new_code = totp.now()
    print('New verification code:', new_code)
    print('New code generation time:', time.time())
    
    # Verify with new code
    print('Verify with new code:')
    new_verify = auth.verify_mfa(username, new_code)
    print('Result:', new_verify)
    print('Expected result: Expired code verification fails, new code verification succeeds')
    
    print("\n=== Test Completed ===")
    print("Test Results Summary:")
    print(f"1. Duplicate Registration: {'Passed' if result1 and not result2 else 'Failed'}")
    print(f"2. Password Reset: {'Passed' if not wrong_reset and correct_reset else 'Failed'}")
    print(f"3. MFA Verification: {'Passed' if not wrong_disable and correct_disable else 'Failed'}")
    print(f"4. Login Attempts: {'Passed' if wrong_login['status'] == 'failed' and correct_login['status'] == 'success' else 'Failed'}")
    print(f"5. Code Expiration: {'Passed' if not expired_verify and new_verify else 'Failed'}")
    print(f"5a. Immediate Verification: {'Passed' if immediate_verify else 'Failed'}")

if __name__ == '__main__':
    test_edge_cases() 