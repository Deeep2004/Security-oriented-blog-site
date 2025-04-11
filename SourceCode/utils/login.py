def decode_percent_encoded(string):
    decoded_string = ''
    i = 0
    while i < len(string):
        if string[i] == '%':
            hex_value = string[i + 1:i + 3]
            decoded_string += chr(int(hex_value, 16))
            i += 3
        else:
            decoded_string += string[i]
            i += 1
    return decoded_string


def extract_credentials(request):
    body = request.data.decode("utf-8")
    pair = body.split('&')
    username = None
    password = None

    for info in pair:
        if '=' not in info:
            continue
        key, value = info.split('=')
        if key == 'username':
            username = value
        elif key == 'password':
            password = decode_percent_encoded(value)
    
    return username, password


def validate_password(password):
    special_characters = {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}
    if len(password) < 8:
        return False
    has_lowercase = False
    has_uppercase = False
    has_digit = False
    has_special = False
    for char in password:
        if char.isupper():
            has_uppercase = True
        elif char.islower():
            has_lowercase = True
        elif char.isnumeric():
            has_digit = True
        elif char in special_characters:
            has_special = True
        else:
            return False
    return has_lowercase and has_uppercase and has_digit and has_special

