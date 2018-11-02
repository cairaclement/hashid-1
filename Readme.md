# hashid

## setup
to use this project, run 

    python3 ./hashid.py your_hash_string
    
## prerequisite
you need to have python3 installed on your computer

## what does it do
It tries to tell you what is the hash of the string you gave. You may pass several
paramaters for additional output :
- a ```--help``` which tells you all you can do with the file.
- a ```--john``` which writes the John the Ripper command 
to try to break the password.
- a ```--wikipedia``` which gives you a short description of the hash found.
- a ```--list``` which tells you all the hash known by the util.

## advancement (known hashes)
Currently known hash include :
- MD5
- SHA1
- SHA224
- Adler-32
- CRC-32
- MD2
- bcrypt
- SHA256
- SHA384
- drupal7
- django SHA384
- redmine

yes, we _kinda_ love SHA.
