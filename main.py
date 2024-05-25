import sys
import tkinter as tk
import cryptography
import bcrypt
from cryptography.hazmat.primitives import hashes
import random
import sqlite3
import os


# Database Setup
conn = sqlite3.connect('passwords.db')
conn.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
             website BLOB NOT NULL,
             username BLOB NOT NULL,
             website_password BLOB NOT NULL);''')
conn.close()


def hash_password(password: str):
    # Generate a salt if you want a stronger password protection you can increase the rounds
    salt = bcrypt.gensalt(rounds=14)
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def save_hash_to_file(hashed_password: str, filename: str):
    # Save the hashed password to a file
    with open(filename, 'w') as file:
        file.write(hashed_password)

def load_hash_from_file(filename: str):
    # Load the hashed password from a file
    if os.path.exists(filename):
        if os.path.getsize(filename) > 0:
            with open(filename, 'r') as file:
                hashed_password = file.read().strip()
            return hashed_password
        else:
            print("error, the password file is empty")
            sys.exit(0)
    else:
        print("You currently do not appear to have a master password set.")
        print("there is currently no strength tester, but a long password containing no words or dates is STRONGLY recommended")
        print("please enter your password now")
        enter_masterpassword()
        return load_hash_from_file("hashed_password")


def enter_masterpassword():
    password = input("Password: ")
    password2 = input("Confirm Password: ")
    if password == password2:
        hashed_password = hash_password(password)
        save_hash_to_file(hashed_password, "hashed_password")
        print("Your password has been saved successfully")
    else:
        print("Passwords do not match")
        enter_masterpassword()
def check_password(password: str, hashed_password: str) -> bool:
    # Check the password against the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def input_less_then_128(input_string):
    if len(input_string) <= 128:
        return input_string
    else:
        print('Input must be less than 128 characters.')
        input_string = input()
        input_less_then_128(input_string)
        return input_string

# logic for adding padding to the to be encrypted data
def add_padding(message_bytes, block_size):
    padding_length = block_size - (len(message_bytes) % block_size)
    padding = bytes([padding_length] * padding_length)
    return message_bytes + padding

# logic for removing padding
def remove_padding(padded_bytes):
    padding_length = padded_bytes[-1]
    if padding_length > len(padded_bytes):
        raise ValueError("Invalid padding")
    return padded_bytes[:-padding_length]

# here the password is encoded to bytes and appended with the diversifier and hashed into a 128 bite keystream
def make_keystream(password, variable):
    bytepassword = password.encode("utf-8")
    diversifier = variable.to_bytes(32, "big")
    shake_hash = hashes.Hash(hashes.SHAKE128(128))
    shake_hash.update(bytepassword + diversifier)
    keystream = shake_hash.finalize()
    return keystream

def count_rows_in_passwords_table(conn):
    cursor = conn.cursor()
    cursor.execute('''SELECT COUNT(*) FROM passwords''')
    row = cursor.fetchone()
    if row:
        if row[0] == 0:
            welcome()
            return 1
        else:
            return row[0]
    else:
        return 0

def welcome():
    print("You currently have nothing saved")
    inputinfo(1)

def inputinfo(variable):
    print("please enter your info you want to store")
    print("website")
    website_input = input()
    website = input_less_then_128(website_input)
    print("username")
    username_input = input()
    username = input_less_then_128(username_input)
    print("password for the website")
    website_password_input = input()
    website_password = input_less_then_128(website_password_input)
    encoded_website, encoded_username, encoded_website_password = encodeinfo(password, variable, website, username, website_password)
    conn = sqlite3.connect('passwords.db')
    insert_encoded_message(conn, encoded_website, encoded_username, encoded_website_password)
    conn.close()
    print("data encrypted and stored successfully")

def encodeinfo(password, variable,  website, username, website_password):
    # I am using the row where the data is in as the nonce and adding a 0, 1 or 2
    # to the end based on what thing we are storing
    new_variable = variable * 10
    keystream = make_keystream(password, new_variable)
    encoded_website = encode(keystream, website)
    keystream = make_keystream(password, new_variable+1)
    encoded_username = encode(keystream, username)
    keystream = make_keystream(password, new_variable+2)
    encoded_website_password = encode(keystream, website_password)
    return encoded_website, encoded_username, encoded_website_password

def encode(keystream, message):
    message_bytes = message.encode("utf-8")
    # add padding
    padded_message_bytes = add_padding(message_bytes, len(keystream))
    encoded_message = bytes([padded_message_bytes ^ keystream for padded_message_bytes, keystream in zip(padded_message_bytes, keystream)])
    return encoded_message

def decode(keystream, message):
    decoded_padded_message = bytes([message ^ keystream for message, keystream in zip(message, keystream)])
    decoded_message = remove_padding(decoded_padded_message)
    decoded_message = decoded_message.decode("utf-8")
    return decoded_message

def insert_encoded_message(conn, website, username, website_password):
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO passwords (website, username, website_password)
                      VALUES (?, ?, ?)''', (website, username, website_password))
    conn.commit()  # Commit changes to the database

def retrieve_info_by_row_number(conn, row_number):
    cursor = conn.cursor()
    cursor.execute('''SELECT website, username, website_password FROM passwords
                      LIMIT 1 OFFSET ?''', (row_number - 1,))
    row = cursor.fetchone()
    if row:
        website, username, website_password = row
        return website, username, website_password
    else:
        return None

def display_stored_site(password, variable, website):
    new_variable = variable * 10
    decoded_website = decode(make_keystream(password, new_variable), website)
    return decoded_website

def display_all(password, variable, website, username, website_password):
    new_variable = variable * 10
    decoded_website = decode(make_keystream(password, new_variable), website)
    decoded_username = decode(make_keystream(password, new_variable+1), username)
    decoded_website_password = decode(make_keystream(password, new_variable+2), website_password)
    return decoded_website, decoded_username, decoded_website_password

def viewdata ():
    conn = sqlite3.connect('passwords.db')
    print("You have currently stored data for the following sites")
    print("if you want to access your username and password for a site type the index of the site")
    for i in range(rows):
        index = i + 1  # to help people who count from one
        website, username, website_password = retrieve_info_by_row_number(conn, index)
        print("index", index, ": ", display_stored_site(password, index, website))
    conn.close()

    requestedsite = input()
    try:
        integer_value = int(requestedsite)
        if integer_value > rows:
            print("You don't have that site yet!")
        else:
            conn = sqlite3.connect('passwords.db')
            encrypted_website, encrypted_username, encrypted_website_password = retrieve_info_by_row_number(conn,
                                                                                                            integer_value)
            website, username, website_password = display_all(password, integer_value, encrypted_website,
                                                              encrypted_username, encrypted_website_password)
            print("for", website, "your username is ", username, "and your password is ", website_password)
            conn.close()
    except ValueError:
        print("Input is not a number.")


def login():
    stored_password = load_hash_from_file("hashed_password")
    print("Welcome to Password Manager!")
    print("Please enter your password to log in")
    password = input()
    if check_password(password, stored_password):
        print("login successful!")
        return password
    else:
        print("Wrong password!")
        login()


password = login()
print(password)
while True:
    # main loop
    # Database Setup
    conn = sqlite3.connect('passwords.db')

    # start of the program: we start by checking if the table is empty (FOR NOW)
    rows = count_rows_in_passwords_table(conn)
    conn.close()
    print("Do you want to view your stored data or enter new data?")
    print("Enter 1 to view your stored data")
    print("Enter 2 to enter new data")
    print("Enter 3 to quit the program")
    user_input = input()
    try:
        integer_value = int(user_input)
        if integer_value == 1:
            viewdata()
        elif integer_value == 2:
            inputinfo(rows+1)
        elif integer_value == 3:
            sys.exit(0)
        else:
            print("invalid input")
    except ValueError:
        print("Input is not a number.")


