# Fernet module is imported from the 
# cryptography package 
from cryptography.fernet import Fernet 

crypto_key = Fernet.generate_key()
f = Fernet(crypto_key)

def get_key_value():
    return f

if "__name__" == "__main__":
    print(get_key_value())