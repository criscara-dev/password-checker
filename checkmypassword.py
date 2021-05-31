from typing import List
import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char
    res = requests.get(url)
    # check
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}, check the API and try again')
    return res

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()   
    first5_chars,tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_chars)
    return get_password_leak_count(response,tail)   

def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
         
# pwned_api_check('password123')  

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

# with open('pass.txt') as my_pass:
#     print(my_pass.read())
#     for single_pass in my_pass:
#         print(single_pass)

###########  version 2 with esternal text file:

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