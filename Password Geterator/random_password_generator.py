'''
Random Password Generator v2

Developers:
    Some Guy they call Scooter
    Common Sense Cyber Group

Created: 7/2/2021
Updated: 11/11/2021

Version 2.0.2

Purpose:
    -This script is meant to be a random password generator for different purposes.
    -It will ask the user for some inputs on the type of password they wih to generate, and then output the passwords in a csv file list
    -Removes any characters that the user does not wish to have in their password (for requirements reasons)

Version Notes:
    -As of version 2.0 users are asked for input to change the length and complexity of the passwords

'''
###IMPORT LIBRARIES###
import os
from os.path import dirname
import random
import string

###DEFINE VARIABLES###
project_root = dirname(__file__)   #Defines the root directory the script is currently in
slash = "/"
project_root = f'{project_root}{slash}'
output_file = f'{project_root}password_generator_outputs.csv'

###FUNCTIONS###
#Function to gather the password complexity requirements from the user
def user_input():
    print()

    #Define variables for defaults
    numbers = "Y"
    special_char = "Y"
    upper_lower = "Y"

    #Get the desired complexities from the user
    password_length = input("How long would you like the password to be? (Number only): ")
    numbers = input("Would you like numbers in your password? [Y]             : ")
    special_char = input("Would you like special characters in your password? [Y]  : ")
    upper_lower = input("Would you like a mix of upper and lower case characters in your password? [Y]: ")
    number_generated = input("Home many passwords would you like to generate?          : ")
    remove_chars = input("Please list any characters you wish to exclude []        : ")

    #Error checking for user inputs
    if password_length == "0":
        for x in password_length:
            if x not in string.digits:
                print("ERROR - Password Length MUST be numbers only!")
                quit()
    if number_generated == "0" or number_generated not in string.digits:
        print("ERROR - Number of generated passwords MUST be numbers only!")
        quit()

    return password_length, numbers, special_char, number_generated, upper_lower

#Function to take the userf puts and generate the passwords for the user
def generate(password_length, numbers, special_char, number_generated, upper_lower):
    #Using the user inputs, determine what we need to create and make the appropriate variables
    if numbers == "Y" or numbers == "y" or numbers == "":
        num = string.digits
    else:
        num = ""

    if special_char == "Y" or special_char == "y" or special_char == "":
        spec = string.punctuation
    else:
        spec = ""

    if upper_lower == "Y" or upper_lower == "y" or upper_lower == "":
        letters = string.ascii_lowercase + string.ascii_uppercase
    else:
        letters = string.ascii_lowercase

    #Create the string to pull random things from to create the password
    chars = letters + num + spec

        
    #Set up and actually create the passwords for the user
    random.seed = (os.urandom(1024))

    i = 1
    while i <= int(number_generated):
        pw = ""
        for x in range(int(password_length)):
            pw += ''.join(random.choice(chars))
            
    #Remove any characters that the user does not want
    for char in remove_chars:
        if char in pw:
            new_char = random.choice(chars)

            if new_char == char:
                new_char = random.choice(chars)

            pw.replace(char, new_char)

        print(pw, file=open(output_file, "a"))
        i += 1

###MAIN###
if __name__ == '__main__':
    #Call the function for user input to get the password complexity requirements
    password_length, numbers, special_char, number_generated, upper_lower = user_input()

    #Call the function to actually take the user inputs and generate the requested passwords
    generate(password_length, numbers, special_char, number_generated, upper_lower)

    #Exit
    quit()

'''
End of SCript
'''
