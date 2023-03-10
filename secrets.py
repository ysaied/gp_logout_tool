#!/usr/bin/python3
import datetime
import os

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

# Function to extract key=value pair from text file and convert to Python Dict
# secrets file should follow below schema. Whitespaces are allowed before/after '=' sign
# value=key
# Username=admin
# Password = password123
def get_secrets(file="./secrets.txt"):
    if not os.path.exists(file):
        log4y(f"Secrets File: {file} Not Found")
        log4y(f"{'#'*20}\tApplication Ended with Errors\t{'#'*20}")
        raise ValueError(f"Secrets File: File doesn't Exist {file}")
        return False
    log4y(f"Secrets File: {file} Found")
    with open(file, "r") as secrets_file:
        secrets_lines = secrets_file.readlines()
    secrets = dict()
    log4y(f"Secrets File: Extracting Secrets from {file}")
    for _ in list(map(lambda _: _.strip("\n"), secrets_lines)):
        if _:
            if _.startswith("#") : log4y(f"Secrets File: Comment Line Found")
            else:
                _ = _.split("=")
                secrets[_[0].strip()] = _[1].strip()
    log4y(f"Secrets File: Secrets Ready as Python Dictionary")
    KEYS = str()
    for _ in secrets:
        KEYS += f"{_},"
    KEYS = KEYS.rstrip(",")
    log4y(f"Secrets File: List of Keys found: {KEYS}")
    return secrets
