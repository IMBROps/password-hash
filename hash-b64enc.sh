#!/bin/bash

generate_hash() {
    # Encode the password to base64
    encoded_password=$(echo -n "$1" | base64)

    # Concatenate the encoded password and secret key
    message="${encoded_password}${2}"

    # Generate the hash using sha1sum
    hashed_password=$(echo -n "$message" | sha1sum | cut -d ' ' -f1)

    echo "$hashed_password"
}

print_heading() {
    # Print a patterned heading for the script
    echo "****************************************"
    echo "HASH Password Generator"
    echo "****************************************"
}

main() {
    # Hardcoded secret key
    secret_key="YourSecretKey"

    # Print the heading
    print_heading

    # Ask the user for the desired password
    read -p "Enter your desired password: " password

    # Generate the hash for the password using SHA-1 and the secret key
    hashed_password=$(generate_hash "$password" "$secret_key")

    # Display the generated hash
    echo "Generated Hash: $hashed_password"
}

main
