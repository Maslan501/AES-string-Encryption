import hashlib
import getpass
import random
import string
import sys
import time
import base64
from Crypto.Cipher import AES
from flask import Flask, render_template, request
from flask_uploads import UploadSet, configure_uploads, DEFAULTS

app = Flask(__name__)

file= UploadSet('file', DEFAULTS)


@app.route('/Encrypted', methods=['GET', 'POST'])
def upload():
    form = ReusableForm(request.form)
    if request.method == 'POST' :
        # and 'all' in request.files:
        
        Key = request.form['Key']
        RandomNo = request.form['Random']
        Stringfile = request.form['Stringfile']
        #encrypt(key_prompt(), IV_prompt(), text_prompt())
        #print(key_prompt())
        print(Key)
        print(RandomNo)
        print(Stringfile)
        #return "ciphertext_base64" 
       
    return render_template('upload.html')

def key_prompt():
    """ Prompts the user to enter a key to encrypt and decrypt the ciphertext
    into plaintext. Supports both encrypting and decrypting. """
    
    # Prompts user to enter key
    #print ("Enter the cryptographic key used to encrypt/decrypt the message")
    
    # Length checking loop
    #while True:
    Key = request.form['Key']
    user_input = getpass.getpass(Key)
        
       # if user_input <= 8:
       #     print ("The key you entered is too short. Please try again")
        
        #else:
         #   break
    
    # Hashes the key to create 32 byte string and creates UTF-8 friendy base64
    Key1 = hashlib.sha256(user_input).digest()
    Key_base64 = base64.b64encode(Key1)
    
    print ("Your key is registered as: %s" % (key_base64))
    return Key

def IV_prompt(RandomNo):
    print ("A IV is being generated...")
                
    # Defines character sets
    ascii = string.ascii_letters
    digits = string.digits
    punct = string.punctuation
    charset = ascii + digits + punct
                
    # Size of string
    size = 32
                
    # Generates random string
    rand = ""
    rand.join(RandomNo.choice(charset) for i in range(size))
                
    # Creates IV from random string
    IV = hashlib.sha256(rand).digest()[0:16]
    IV_base64 = base64.b64encode(IV)
                
    # Returns IV to the user
    print ("The IV in base64 is printed below. You must use it to ")
    print ("decrypt the ciphertext. It is ok to send the IV with the")
    print ("ciphertext - an attacker cannot us the IV against you")
                
    print ("    IV: %s" % (IV_base64))
    return IV
                
    
def text_prompt(Stringfile):
   
        plaintext = Stringfile
        
        return plaintext
    
def encrypt(key, IV, plaintext):
        print(key)
        print(IV)
        print(plaintext)
        # Sets encryption mode
        mode = AES.MODE_CBC
    
    # Main encryption function
        encryptor = AES.new(key, mode, IV)
        ciphertext = encryptor.encrypt(plaintext)
    
    # Converts binary ciphertext into base64
        ciphertext_base64 = base64.b64encode(ciphertext)
    
    # Gives user encrypted base64 string
        print ("You have successfully encrypted your message using")
        print ("AES-256. The result is given to you encoded in")
        print ("base64. You must decode it into it's raw form before")
        print ("using it. This program does it for you automatically")
        print ("when you select decrypt.")
    
        print (ciphertext_base64)

        return ciphertext_base64


def decrypt(key, IV, ciphertext):
    """ Main decryption function. Decrypts the ciphertext (which would already
    be turned from base64 to raw binary via text_prompt() """
    
    # Sets encryption mode
    mode = AES.MODE_CBC
    
    # Main encryption function
    decryptor = AES.new(key, mode, IV)
    plaintext = decryptor.decrypt(ciphertext)
    
    # Gives the user the result from decryption
    print ("We have decrypted the message from your information")
    print ("If it is gibberish, make sure to check if the IV, ")
    print ("key, or ciphertext is correct")
    
    print (plaintext)
        
    return(plaintext)

if __name__ == '__main__':
   app.run(debug = True)