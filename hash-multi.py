import hashlib

def generate_hash(password, algorithm, secret_key):

    # Concatenate the password and secret key
    message = password.encode() + secret_key.encode()

    # Create a new hash object based on the selected algorithm
    if algorithm == 'md5':
        hash_object = hashlib.md5()
    elif algorithm == 'sha1':
        hash_object = hashlib.sha1()
    elif algorithm == 'sha256':
        hash_object = hashlib.sha256()
    elif algorithm == 'sha512':
        hash_object = hashlib.sha512()
    else:
        print("Invalid algorithm selected.")
        return None

    # Update the hash object with the message
    hash_object.update(message)

    # Generate the hexadecimal representation of the hash
    hashed_password = hash_object.hexdigest()

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


    # Print options for hashing algorithms
    print("Available Hashing Algorithms:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")
    print("4. SHA512")

    # Ask the user to select a hashing algorithm
    algorithm_choice = input("Select the desired hashing algorithm (1/2/3/4): ")

    # Dictionary to map user input to algorithm names
    algorithm_mapping = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha256',
        '4': 'sha512'
    }

    # Get the selected algorithm name from the dictionary
    selected_algorithm = algorithm_mapping.get(algorithm_choice)
    if not selected_algorithm:
        print("Invalid choice. Exiting.")
        return

    # Ask the user for the desired password
    password = input("Enter your desired password: ")

    # Generate the hash for the password using the selected algorithm and the secret key
    hashed_password = generate_hash(password, selected_algorithm, secret_key)

    # Display the generated hash
    if hashed_password:
        print(f"Generated Hash using {selected_algorithm.upper()}: {hashed_password}")

if __name__ == "__main__":
    main()
