#!/usr/bin/python3
import time
import datetime
import requests
import xmltodict
import os

from soc_mail import mail_header,mail_trailer,mail_section_1

requests.packages.urllib3.disable_warnings()
log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)


# csv_4y = with open("./text.csv", "w") as csv_file: csv_file.write(_)


def fw_key(fw_ip, uname, pwd):
    # function to get API key from username/password
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "type": "keygen",
        "user": {uname},
        "password": {pwd}
    }
    api_hdr = {}
    api_pld = {}

    for _ in range(3):
        try:
            log4y(f"PAN-OS API: Connection Requested, Firewall {fw_ip}")
            response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
        except:
            log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable, will retry in 5 secs")
            time.sleep(5)
        else:
            log4y(f"PAN-OS API: Connection Succeeded, Firewall {fw_ip} Key Retrieved")
            if "Invalid Credential" in response.text:
                log4y(f"PAN-OS API: Invalid Credential, Firewall {fw_ip}")
                return False
            elif "key" in response.text:
                key = xmltodict.parse(response.text)["response"]["result"]["key"]
                return key
    log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable, max. retries exceeded")
    # raise Exception(f" PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable, max. retries exceeded")
    return False


def fw_gp_ext(fw_ip, fw_key):
    # function to return list of connected GP users in a list of dictionaries
    # each connected user has an entry on the list with dictionary of key/value pairs
    # Sample of user dictionary {'Username': '', 'Client-Hostname': '', 'Client-OS': '', 'Client-Source-IP': ''}
    # Duration Connected and Client-Country added to code @25Dec22
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "key": fw_key,
        "type": "op",
        "cmd": "<show><global-protect-gateway><current-user/></global-protect-gateway></show>"
    }
    api_hdr = {}
    api_pld = {}
    try:
        log4y(f"PAN-OS API: Request GP-Gateway Connected Users, Firewall {fw_ip}")
        response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
    except:
        log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
        raise ValueError(f" PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
    else:
        log4y(f"PAN-OS API: Analyzing GP-Gateway Connected Users, Firewall {fw_ip}")
        result = xmltodict.parse(response.text)["response"]["result"]
        # print(response.text)
        gp_users = []
        if result:
            log4y(f"PAN-OS API: Found Users Connected to GP-Gateway, Firewall {fw_ip}")
            if type(result["entry"]) == dict:
                # In case there is only 1 connected GP user, FW returns the result as Dict
                # While if there are more than 1 connected GP user, FW returns the result as List
                # In order to unify the return for the code, if FW returns Dict, it is added to a List
                result["entry"] = [result["entry"]]
            for _ in result["entry"]:
                user = dict()
                user["Username"] = _["username"]
                user["Client-Hostname"] = _["computer"]
                user["Client-OS"] = _["client"]
                user["Client-Source-IP"] = _["client-ip"]
                user["Client-Country"] = _["source-region"]
                user["Login-Time"] = _["login-time"]
                user["Duration-Connected"] = int(time.time()) - int(_["login-time-utc"])
                gp_users.append(user)
                log4y(f"PAN-OS API: User \"{user['Username']}\" Connected to GP-Gateway, Firewall {fw_ip}")
        else:
            log4y(f"PAN-OS API: NO Users Connected to GP-Gateway, Firewall {fw_ip}")
        return gp_users


def fw_gp_lst(gp_ext):
    # function to return list of connected GP users in a List
    # It only returns the usernames
    # The input of the function is the List coming from 'fw_gp_ext' function
    gp_users = []
    for _ in gp_ext:
        gp_users.append(_["Username"])
    return gp_users


def fw_gp_gw_id(fw_ip, fw_key):
    # function to get the GP Gateway ID
    # PAN-OS CLI show global-protect-gateway gateway, the output from "Tunnel Name"
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "key": fw_key,
        "type": "op",
        "cmd": "<show><global-protect-gateway><gateway/></global-protect-gateway></show>"
    }
    api_hdr = {}
    api_pld = {}
    try:
        log4y(f"PAN-OS API: Request GP-Gateway Name, Firewall {fw_ip}")
        response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
    except:
        log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
        raise ValueError(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
    else:
        if "portal" in response.text:
            gateway_name = xmltodict.parse(response.text)["response"]["result"]["entry"]["portal"]
            log4y(f"PAN-OS API: GP-Gateway Name is {gateway_name}, Firewall {fw_ip}")
            return gateway_name
        else:
            log4y(f"PAN-OS API: GP Not Running on this Firewall, Firewall {fw_ip}")
            raise ValueError(f"PAN-OS API: GP Not Running on this Firewall, Firewall {fw_ip}")
    return False


def fw_gp_duplicates(gp_lst, gp_ext, fw_ip, fw_key,csv_path):
    gp_set = set(gp_lst)
    gp_duplicate_lst = []
    for _ in gp_set:
        log4y(f"PAN-OS API: User {_} has {gp_lst.count(_)} Active GP Sessions") if gp_lst.count(_) > 1 else None
        gp_duplicate_lst.append(_) if gp_lst.count(_) > 1 else None

    gateway_name = fw_gp_gw_id(fw_ip=fw_ip, fw_key=fw_key)

    # create tmp file for the email to SoC
    with open("./soc_mail.txt", "w") as soc_mail_body:
        soc_mail_body.write(mail_header)
        [soc_mail_body.write(f"{_}\n") for _ in gp_duplicate_lst]
        soc_mail_body.write(mail_section_1)

    for _ in gp_duplicate_lst:
        disconnection_table = dict()
        for entry in gp_ext:
            if _ == entry["Username"]:
                disconnection_table[entry["Duration-Connected"]] = entry["Client-Hostname"]
                csv_entry = f'{datetime.datetime.now().strftime("%Y%m%d%H%M")},' \
                            f'{entry["Username"]},' \
                            f'{datetime.datetime.now().strftime("%b.%d.%Y")},' \
                            f'{datetime.datetime.now().strftime("%H:%M:%S")},' \
                            f'{entry["Client-Hostname"]},' \
                            f'{entry["Client-Source-IP"]},' \
                            f'{entry["Client-Country"]},' \
                            f'{entry["Login-Time"]}' \
                            f'\n'
                with open(csv_path, "a+") as csv_file:
                    csv_file.write(csv_entry)

                with open("./soc_mail.txt", "a+") as soc_mail_body:
                    soc_mail_body.write(csv_entry)

        # reverse = True for Descending Order .. i.e. place the higher connection-duration at the top
        disconnection_lst = sorted(disconnection_table.items(), reverse=True)
        # remove the first element on the list .. remove the session with higher connection-duration
        disconnection_lst.pop(0)
        disconnection_table = dict(disconnection_lst)

        for key, value in disconnection_table.items():
            cmd = f"""
            <request>
                <global-protect-gateway>
                    <client-logout>
                        <user>{_}</user>
                        <computer>{value}</computer>
                        <reason>force-logout</reason>
                        <gateway>{gateway_name}</gateway>
                    </client-logout>
                </global-protect-gateway>
            </request>
            """
            # print(cmd)
            api_url = f"https://{fw_ip}/api"
            api_prm = {
                "key": fw_key,
                "type": "op",
                "cmd": cmd
            }
            api_hdr = {}
            api_pld = {}
            try:
                log4y(f"PAN-OS API: Request GP-Gateway Disconnect User {_} Host {value}, Firewall {fw_ip}")
                response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
            except:
                log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
            else:
                if "success" in response.text:
                    log4y(
                        f"PAN-OS API: GP Session for User {_} Host {value} Disconnected Successfully, Firewall {fw_ip}")
                else:
                    log4y(f"PAN-OS API: GP Session for User {_} Host {value} Disconnection Failure, Firewall {fw_ip}")

    with open("./soc_mail.txt", "a+") as soc_mail_body:
        soc_mail_body.write(mail_trailer)

    return gp_duplicate_lst

