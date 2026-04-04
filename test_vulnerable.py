import os
import subprocess

def insecure_function(user_input):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    # Command injection vulnerability
    result = subprocess.call(f"echo {user_input}", shell=True)
    return query, result

def weak_crypto():
    import random
    # Weak random number generation
    key = random.randint(1, 100)
    return key

if __name__ == "__main__":
    print(insecure_function("test"))
    print(weak_crypto())