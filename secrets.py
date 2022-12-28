#!/usr/bin/python3
import datetime
import os

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

# Function to extract key=value pair from text file and convert to Python Dict
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
        _ = _.split("=")
        secrets[_[0]] = _[1]
    log4y(f"Secrets File: Secrets Ready as Python Dictionary")
    return secrets
