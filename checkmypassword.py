import requests 
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char 
    # query_char = 'password123' -> CBFDAC6008F9CAB4083784CBD1874F76618D2A97 in SHA1 ... so basically we are giving away just 'CBFDA'    
    res = requests.get(url)
    # check we are getting a response
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}, check the API and try again')
    return res

def pwned_api_check(password):
    # check if the password exist in the API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()   
    first5_chars,tail = sha1password[:5], sha1password[5:]
    # Since we don't trust anyone and we want to be secure so we are giving away just the first 5 chars
    response = request_api_data(first5_chars) 
    # the API return as a response the list of the tail hashed passwords
    return get_password_leak_count(response,tail)   


# helper function    
# 'hashes' is a collections: ex. -> C6008F9CAB4083784CBD1874F76618D2A97:1  C6008F9CAB4083784CGHF874F76618D2S97:56 ...
def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines()) # -> ['C6008F9CAB4083784CBD1874F76618D2A97','1'] ['C6008F9CAB4083784CGHF874F76618D2S97','56'] ...
    # loop throough all the 'hashes' and check our tail against
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
         
# pwned_api_check('password123')  

#########################################################
###########  V 1.0.0 with esternal text file: ###########
# def main(args):
#     for password in args:
#         count = pwned_api_check(password)
#         if count:
#             print(f'{password} was found {count} times... Yout should change your password!')
#         else:
#             print(f'{password} NOT found. You are good to go!')
#     return 'done!'
    
# if __name__ == '__main__':
#     sys.exit(main(sys.argv[1:]))   

##############################################################################
###########  V 1.0.1 More secure version with external text file: ###########

with open('pass.txt') as passwords:
    # skip first line of instructions
    next(passwords)
    list_passwords = [line.rstrip('\n') for line in passwords]
    # print(list_passwords)  
    for password in list_passwords:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... Yout should change your password!')
        else:
            print(f'{password} NOT found. You are good to go!')