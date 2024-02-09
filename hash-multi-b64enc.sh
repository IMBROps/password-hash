#!/bin/bash

generate_hash() {
    # Encode the password to bytes and then base64 encode it
    encoded_password=$(echo -n "$1" | base64)

    # Concatenate the encoded password and secret key
    message="${encoded_password}${3}"

    # Create a new hash object based on the selected algorithm
    case $2 in
        md5)
            hash_object=$(echo -n "$message" | md5sum | cut -d ' ' -f1)
            ;;
        sha1)
            hash_object=$(echo -n "$message" | sha1sum | cut -d ' ' -f1)
            ;;
        sha256)
            hash_object=$(echo -n "$message" | sha256sum | cut -d ' ' -f1)
            ;;
        sha512)
            hash_object=$(echo -n "$message" | sha512sum | cut -d ' ' -f1)
            ;;
        *)
            echo "Invalid algorithm selected."
            return 1
            ;;
    esac

    echo "$hash_object"
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

    # Print options for hashing algorithms
    echo "Available Hashing Algorithms:"
    echo "1. MD5"
    echo "2. SHA1"
    echo "3. SHA256"
    echo "4. SHA512"

    # Ask the user to select a hashing algorithm
    read -p "Select the desired hashing algorithm (1/2/3/4): " algorithm_choice

    # Dictionary to map user input to algorithm names
    case $algorithm_choice in
        1)
            selected_algorithm="md5"
            ;;
        2)
            selected_algorithm="sha1"
            ;;
        3)
            selected_algorithm="sha256"
            ;;
        4)
            selected_algorithm="sha512"
            ;;
        *)
            echo "Invalid choice. Exiting."
            return 1
            ;;
    esac

    # Ask the user for the desired password
    read -p "Enter your desired password: " password

    # Generate the hash for the password using the selected algorithm and the secret key
    hashed_password=$(generate_hash "$password" "$selected_algorithm" "$secret_key")

    # Display the generated hash
    if [[ -n "$hashed_password" ]]; then
        echo "Generated Hash using ${selected_algorithm^^}: $hashed_password"
    fi
}

main
