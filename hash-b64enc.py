import hashlib
import base64

def generate_hash(password, secret_key):

    # Encode the password to bytes and then base64 encode it
    encoded_password = base64.b64encode(password.encode()).decode()

    # Concatenate the password and secret key
    message = encoded_password.encode() + secret_key.encode()

    # Create a new SHA-256 hash object
    sha1_hash = hashlib.sha1()

    # Update the hash object with the message
    sha1_hash.update(message)

    # Generate the hexadecimal representation of the hash
    hashed_password = sha1_hash.hexdigest()

    return hashed_password


def print_heading():
    """
    Heading.
    """
    print("*" * 40)
    print("HASH Password Generator".center(40))
    print("*" * 40)


def main():
    # Hardcoded secret key
    secret_key = "YourSecretKey"

    # Print the heading
    print_heading()


    # Ask the user for the desired password
    password = input("Enter your desired password: ")

    # Generate the hash for the password using SHA-1 and the secret key
    hashed_password = generate_hash(password, secret_key)

    # Display the generated hash
    print("Generated Hash:", hashed_password)

if __name__ == "__main__":
    main() 


