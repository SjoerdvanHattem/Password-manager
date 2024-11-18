import sys
import tkinter as tk
import cryptography
import bcrypt
from cryptography.hazmat.primitives import hashes
import random
import sqlite3
import os
# current password for database : Test

# Database Setup
conn = sqlite3.connect('passwords.db')
conn.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
             website BLOB NOT NULL,
             username BLOB NOT NULL,
             website_password BLOB NOT NULL,
             diversifier_username INTEGER NOT NULL,
             diversifier_website INTEGER NOT NULL,
             diversifier_password INTEGER NOT NULL);''')
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

# generates a random number that is used as a diversifier later
def generate_random_div():
    div = random.randint(0, 4294967295)
    conn = sqlite3.connect('passwords.db')
    if check_div(div, conn):
        return div
    else:
        conn.close()
        return generate_random_div()

# checks if the div is already used in the database if it's already used it returns False and if it's not already used it returns True
def check_div(div, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM passwords WHERE diversifier_username = ? OR diversifier_website = ? OR diversifier_password = ?", (div, div , div,))
    if cursor.fetchone():
        return False
    else:
        return True

    # returns the diversifier from the id provided
    # for the username div use choice = 0
    # for the website div use choice = 1
    # for the password div use choice = 2
def get_diversifier(id, choice):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    if choice == 0:
        cursor.execute("SELECT diversifier_username FROM passwords WHERE id = ?", (id,))
        div = cursor.fetchone()[0]
        conn.close()
        return div
    elif choice == 1:
        cursor.execute("SELECT diversifier_website FROM passwords WHERE id = ?", (id,))
        div = cursor.fetchone()[0]
        conn.close()
        return div
    elif choice == 2:
        cursor.execute("SELECT diversifier_password FROM passwords WHERE id = ?", (id,))
        div = cursor.fetchone()[0]
        conn.close()
        return div

def count_rows_in_passwords_table(conn):
    cursor = conn.cursor()
    cursor.execute('''SELECT COUNT(*) FROM passwords''')
    row = cursor.fetchone()
    if row:
        if row[0] == 0:
            conn.close()
            welcome()
            return 1
        else:
            conn.close()
            return row[0]
    else:
        conn.close()
        return 0

def welcome():
    print("You currently have nothing saved")
    inputinfo()

def inputinfo():
    print("please enter your info you want to store")
    print("enter website")
    website_input = input()
    website = input_less_then_128(website_input)
    print("username")
    username_input = input()
    username = input_less_then_128(username_input)
    print("password for the website")
    website_password_input = input()
    website_password = input_less_then_128(website_password_input)
    (encoded_website, encoded_username, encoded_website_password, diversifier_website,
     diversifier_username, diversifier_password) = encodeinfo(password, website, username, website_password)
    conn = sqlite3.connect('passwords.db')
    insert_encoded_message(conn, encoded_website, encoded_username, encoded_website_password, diversifier_website, diversifier_username, diversifier_password)
    conn.close()
    print("data encrypted and stored successfully")


# it's fucking ugly but I don't care
def generate_username_div(websitediv):
    div = generate_random_div()
    if div == websitediv:
         return generate_random_div()
    else:
        return div

def generate_password_div(websitediv, usernamediv):
    div = generate_random_div()
    if div == websitediv or div ==usernamediv:
        return generate_random_div()
    else:
        return div



def encodeinfo(password, website, username, website_password):
    diversifier_website = generate_random_div()
    diversifier_username = generate_username_div(diversifier_website)
    diversifier_password = generate_password_div(diversifier_website, diversifier_username)
    keystream = make_keystream(password, diversifier_website)
    encoded_website = encode(keystream, website)
    keystream = make_keystream(password, diversifier_username)
    encoded_username = encode(keystream, username)
    keystream = make_keystream(password, diversifier_password)
    encoded_website_password = encode(keystream, website_password)
    return encoded_website, encoded_username, encoded_website_password, diversifier_website, diversifier_username, diversifier_password

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

def insert_encoded_message(conn, website, username, website_password, diversifier_website, diversifier_username, diversifier_password):
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO passwords (website, username, website_password, diversifier_website, diversifier_username, diversifier_password)
                      VALUES (?, ?, ?, ?, ?, ?)''', (website, username, website_password, diversifier_website, diversifier_username, diversifier_password))
    conn.commit()  # Commit changes to the database
    conn.close()


def retrieve_info_by_row_number(conn, row_number):
    cursor = conn.cursor()
    cursor.execute('''SELECT website, username, website_password FROM passwords 
                      WHERE id = ?''', (row_number ,))
    row = cursor.fetchone()
    if row:
        website, username, website_password = row
        return website, username, website_password
    else:
        return None

def retrieve_divs_by_row_number(conn, row_number):
    cursor = conn.cursor()
    cursor.execute('''SELECT diversifier_website, diversifier_username, diversifier_password FROM passwords 
                         WHERE id = ?''', (row_number,))
    row = cursor.fetchone()
    if row:
        diversifier_website, diversifier_username, diversifier_password = row
        return diversifier_website, diversifier_username, diversifier_password
    else:
        return None

def remove_row(row_number):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    if row_exists(row_number, conn):
        cursor.execute("DELETE FROM passwords WHERE id = ?", (row_number,))
        conn.commit()
        print(f"Row {row_number} deleted successfully.")
    else:
        print(f"Row {row_number} does not exist.")
    conn.close()


def display_stored_site(password,website, diversifier_website):

    decoded_website = decode(make_keystream(password, diversifier_website), website)
    return decoded_website

def display_all(password, website, username, website_password, diversifier_website, diversifier_username, diversifier_password):
    decoded_website = decode(make_keystream(password, diversifier_website), website)
    decoded_username = decode(make_keystream(password, diversifier_username), username)
    decoded_website_password = decode(make_keystream(password, diversifier_password), website_password)
    return decoded_website, decoded_username, decoded_website_password


def row_exists(row_number, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM passwords WHERE id = ?", (row_number,))
    row_exists = cursor.fetchone() is not None
    return row_exists


def viewdata():
    conn = sqlite3.connect('passwords.db')
    print("You have currently stored data for the following sites")
    print("if you want to access your username and password for a site type the index of the site")

    cursor = conn.cursor()
    cursor.execute('''SELECT website, id, diversifier_website FROM passwords''')
    rows = cursor.fetchall()
    conn.close()

    for i, row in enumerate(rows):
        rownr = row[1]
        website = row[0]
        div_website = row[2]
        print("index", rownr, ": ", display_stored_site(password, website, div_website))

    requestedsite = input()
    try:
        rownr = int(requestedsite)
        conn = sqlite3.connect('passwords.db')
        if not row_exists(rownr, conn):
            print("You don't have that site yet!")
            conn.close()
        else:
            diversifier_website, diversifier_username, diversifier_password = retrieve_divs_by_row_number(conn, rownr)
            encrypted_website, encrypted_username, encrypted_website_password = retrieve_info_by_row_number(conn, rownr)
            website, username, website_password = (display_all
                                                   (password, encrypted_website, encrypted_username,
                                                    encrypted_website_password, diversifier_website,
                                                    diversifier_username, diversifier_password))
            print("for", website, "your username is ", username, "and your password is ", website_password)
            conn.close()
    except ValueError:
        print("Input is not a number or input is an invalid index")


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
while True:
    conn = sqlite3.connect('passwords.db')
    rows = count_rows_in_passwords_table(conn)
    conn.close()
    print("rows read = " + str(rows) )
    print("Do you want to view your stored data, enter new data, remove a row, or quit the program?")
    print("Enter 1 to view your stored data")
    print("Enter 2 to enter new data")
    print("Enter 3 to remove a row")
    print("Enter 4 to quit the program")
    user_input = input()
    try:
        integer_value = int(user_input)
        if integer_value == 1:
            viewdata()
        elif integer_value == 2:
            inputinfo()
        elif integer_value == 3:
            print("Enter the index of the row you want to remove")
            row_to_remove = int(input())
            remove_row(row_to_remove)
        elif integer_value == 4:
            sys.exit(0)
        else:
            print("invalid input")
    except ValueError:
        print("Input is not a number.")