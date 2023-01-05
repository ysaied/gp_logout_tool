#!/usr/bin/python3
import time
import datetime
import requests
import xmltodict
import os

requests.packages.urllib3.disable_warnings()
log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)


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


def gp_user_logout(fw_ip, fw_key, username, computer, gateway_name):
    # function to force GP User logout via PAN-OS API
    # GP logout is forced by username and computer name i.e. hostname
    # GP Gateway name is needed, and taken from other function fw_gp_gw_id
    api_url = f"https://{fw_ip}/api"
    cmd = f"""
    <request>
        <global-protect-gateway>
            <client-logout>
                <user>{username}</user>
                <computer>{computer}</computer>
                <reason>force-logout</reason>
                <gateway>{gateway_name}</gateway>
            </client-logout>
        </global-protect-gateway>
    </request>
    """
    # print(cmd)
    api_prm = {
        "key": fw_key,
        "type": "op",
        "cmd": cmd
    }
    api_hdr = {}
    api_pld = {}
    try:
        log4y(f"PAN-OS API: Request GP-Gateway Disconnect User - user:{username} Host:{computer}, Firewall {fw_ip}")
        response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
    except:
        log4y(f"PAN-OS API: GP-Gateway Disconnect User Failure - user:{username} Host:{computer}, Firewall:{fw_ip}")
        raise ValueError(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
    else:
        if "success" in response.text:
            log4y(
                f"PAN-OS API: GP-Gateway Disconnect User Successful - user:{username} Host:{computer}, Firewall {fw_ip}")
        else:
            log4y(
                f"PAN-OS API: PAN-OS API: GP-Gateway Disconnect User Failure - user:{username} Host:{computer}, Firewall:{fw_ip}")
            log4y(f"PAN-OS API: {response.text}")


def fw_gp_duplicates(gp_lst, gp_ext, fw_ip, fw_key, csv_path):
    # function to find out Duplicate GP sessions. Inputs are GP connected Users summary list and extended details list
    # Users summary set remove duplicate users from summary list
    gp_set = set(gp_lst)
    # Define new list that will hold duplicate Users summary
    gp_duplicate_lst = []
    for _ in gp_set:
        log4y(f"PAN-OS API: User {_} has {gp_lst.count(_)} Active GP Sessions") if gp_lst.count(_) > 1 else None
        gp_duplicate_lst.append(_) if gp_lst.count(_) > 1 else None

    # Get GP Gateway Name by calling fw_gp_gw_id function
    gateway_name = fw_gp_gw_id(fw_ip=fw_ip, fw_key=fw_key)
    # Define new list that will hold duplicate Users extended details
    gp_duplicate_ext = []
    # Loop for each User in the Duplicate Summary List
    for _ in gp_duplicate_lst:
        # Define Key/Value that holds connection_duration:hostname for each active connection for that user
        disconnection_table = dict()
        # Search for duplicate user name in the GP extended details list
        for entry in gp_ext:
            if _ == entry["Username"]:
                gp_duplicate_ext.append(entry)
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
        # reverse = True for Descending Order .. i.e. place the higher connection-duration at the top
        disconnection_lst = sorted(disconnection_table.items(), reverse=True)
        # remove the first element on the list .. remove the session with higher connection-duration
        disconnection_lst.pop(0)
        disconnection_table = dict(disconnection_lst)

        for key, value in disconnection_table.items():
            gp_user_logout(fw_ip=fw_ip, fw_key=fw_key, username=_, computer=value, gateway_name=gateway_name)

    result = {
        "GP_DUPLICATE_SUMMARY": gp_duplicate_lst,
        "GP_DUPLICATE_EXTENDED": gp_duplicate_ext
    }
    return result
