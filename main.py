#!/usr/bin/python3
from Header import *
import sys
import utils.colors

# (https://github.com/santoru/shcheck)

def banner(url):
    print("")
    print(utils.colors.colorize("abab",'error'))
    print("======================================================")
    print(" > ./main.py ", url)
    print("------------------------------------------------------")
    print(" Simple tool to check security headers on a webserver ")
    print("======================================================")
    print("")

if __name__ == "__main__":
    header = Header(url=sys.argv[1])
    banner(sys.argv[1])
    print(header.list_of_headers(), len(header.list_of_headers()))
    header.information_leakage_analysis()
    print(header.cookie_analysis())
        