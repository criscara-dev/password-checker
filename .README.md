# Have I been pawned?

This is my first cool project in Python, the purpose is let you type in the console some passwords and check if they have been leaked in the past;

For this purpose I could have just used the popular website: _https://haveibeenpwned.com/_ that let you check if your email or password has been pawned.😱

While I don't have iny concern to enter my email ( that's public so anyone can find it and email me! ) what about my password? 🤔
Personally, I don't think it's always a good idea to send my password over the itnernet because, even if the website connection is encrypted/secure via a https protocol, when I press submit my password is sent through the internet to the website server and someone could be on the middle (Man in the Middle attack) and intercepted it.

As you guessed, there's a secure way to do that and that involve some coding.
So, the more secure way to doing it is built a password checker using the [haveibeenpwned](https://haveibeenpwned.com/API/v3) Password API. (When it comes to security sometimes the best thing is to trust no one).

There're many service out there that under the hood has implemented this type of check like 1passord, keeper, sticky passord etc.

## How I built my first password checker in Python

1. Which module do we need for this project?

- The **_request_** : to be able request data via the internet
- The **_hashlib_** : to hash a password since we don't want to send our password (that is going to be stored in their database)
- The **_sys_** : to be able to pass arguments in Terminal (😅 the passwords to check)

```python
import requests
import hashlib
import sys
```

2. First function to need to write is the one we need to establish a connection to the API and get a response:

```python
# url = 'https://api.pwnedpasswords.com/range/'+ 'CBFDA'
# res = requests.get(url)
# print(res)

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char
    res = requests.get(url)
    # check
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}, check the API and try again')
    return res
```

## So, let's learn the Password API

**Hashing**
The ideas is not to send over the internet the real password, in fact you should never store user password to a DB without hashing the password first;
Since we're using the Password API, and we want to use a 'fast' encryption algorithm, we used the SHA1.
[Sha1 hash generator](https://passwordsgenerator.net/sha1-hash-generator/)
password123 = CBFDAC6008F9CAB4083784CBD1874F76618D2A97 in SHA1.

> Hashing is idempotent, or if you know pretty well JS, it's like a Pure function: giving the same inout (password) it always return the same value (hash)

Plus, to improve anonimity, instead of give to the API the entire hash of a password, we just gave a little bit of it, just the first 5 characters.
We are applying here a 'key anonimity technique' to dont give personal information to a website;
Big Companies do that to track online without know exactly who we are.

> The idea here is to give only the first 5 characters of the hashed password and the API send us back a list of all hashed 'leaked' password starting with those 5 characters.
> On our side we can then check the 'tail' rest of our hashed password against the list and discover it it has been leaked.

## what to do with the response?

We need to create a function to read the response:
Now we need to create a function that check the tail of the hashed password and how many times have been hacked against our password
This way we get hundreds od hashed passwords starting with these 5 chars
:<number> is the number of time the password has been leaked.

```python
def pwned_api_check(password):
#Check the password if it exists in API response using the haslib library/methods...
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars,tail = sha1password[:5], sha1password[5:]
    # here we pass the first 5 chars for the check on the hased password
    response = request_api_data(first5_chars)
    return get_password_leak_count(response,tail)

# temporarely function just to check we get the lst of hashed-leaked passwords, d=not for production! 😅
# that is going to be replaced with the function: get_password_leak_count()
def read_response(response):
    print(response.text)
    # FHSEU347RG23HYGJ432Y3253BBNN:2
    # FHSEUGFYW4G55H432Y325748HBFF:4
    # XHUAQIW3B4IR78YE3TF483CUIFHG:1
    #...
```

```python

# to implement...
def get_password_leak_count(hashes, hash_to_check):
    pass
    # check if the password exist in the API response
```

## Implementing: get_password_leak_count()

```python
def get_password_leak_count(hashes, hash_to_check):
    # this line to get a 'tuple comprehension' that has the number of leaks for hash
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # print(h, count) # XHUAQIW3B4IR78YE3TF483CUIFHG 1
        #at this point I need to check from all the hashes leaked if mine is there (I do not provive this to the service, is only on my machine)
        if h == hash_to_check: # hash_to_check is stored securely in the 'tail' parameter in the previous function...
            return count
    return 0
```

## last create a main fuction that is going to receive the arguments that we give in the terminal

```python
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... Yout should change your password!')
        else:
            print(f'{password} NOT found. You are good to go!')
    return 'done!'

# if we want this file to just run if it is the main file to run and not just imported:
if __name__ == '__main__':
    # just to be sure that the system call just exit and brign us back to the CLI
    sys.exit(main(sys.argv[1:]))
```

---

...
last but not the least,
we are passing our password in the Terminal and this information is stored in our machine memory (try arrow up ;) ),
and this is not super secure,
the password are stored into our machine as well, so if we want to be completel;y safe against possible hackers, we can read this password froma text file.

#### implement pass a password from a text file

Last, to improve our app security and don't store passwords in our computer, we can read the file that contain the passwords and do our check.
Let's comment out our function main() and instead let's read from a txt file.

```python

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
```
