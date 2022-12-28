#!/usr/bin/python3
import datetime
import time
import os

from secrets import get_secrets
from pan_fw import fw_key, fw_gp_ext, fw_gp_lst, fw_gp_duplicates
from soc_mail import soc_mail

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)
ise_gp_del = lambda fw_gp, ise_gp: list(filter(lambda _: _ not in fw_gp, ise_gp))
ise_gp_add = lambda fw_gp, ise_gp: list(filter(lambda _: _ not in ise_gp, fw_gp))


def csv_log(csv_dir="."):
    csv_fname = f'/{datetime.datetime.now().strftime("%Y-%m.csv")}'
    csv_path = csv_dir + csv_fname
    csv_header = "SN,Username,Date,Time,Endpoint Hostname,Public IP,Country,GP Login Time\n"
    if not os.path.exists(csv_path):
        with open(csv_path, "a+") as csv_file:
            csv_file.write(csv_header)
    return csv_path


# Create Header
log4y(f"{'#' * 20}\tGlobalProtect Logout Tool Started\t{'#' * 20}")

credentials = get_secrets("secrets.txt")
#credentials = get_secrets("/home/ysaied/gp_logout/secrets.txt")

fw_ip = credentials["FW_IP"]
fw_uname = credentials["FW_UNAME"]
fw_pwd = credentials["FW_PWD"]

mail_srv_url = credentials["MAIL_SRV_URL"]
mail_srv_port = credentials["MAIL_SRV_Port"]
mail_from = credentials["MAIL_FROM"]
mail_password = credentials["MAIL_PWD"]
mail_to = credentials["MAIL_TO"]

csv_dir = credentials["CSV_Dir"]

if __name__ == '__main__':
    # create the CSV file if not exists
    # insert CVS file header
    csv_path = csv_log(csv_dir=csv_dir)

    # Retrieve Firewall API Auth-Key from Username/Password
    # API-Key can be given directly without using Username/Password for enhanced security operation
    key = fw_key(fw_ip=fw_ip, uname=fw_uname, pwd=fw_pwd)
    if key:
        fw_gp_users_ext = fw_gp_ext(fw_ip=fw_ip, fw_key=key)
        # print(fw_gp_users_ext)
        fw_gp_users_sum = fw_gp_lst(fw_gp_users_ext)
        # print(fw_gp_users_sum)
        gp_duplicate_lst = fw_gp_duplicates(fw_gp_users_sum, fw_gp_users_ext, csv_path=csv_path,fw_ip=fw_ip, fw_key=key)
        # Send SoC Email if there was duplicate sessions
        if (gp_duplicate_lst):
            with open("./soc_mail.txt", "r") as soc_mail_body:
                mail_body = soc_mail_body.read()
            soc_mail(mail_srv_add=mail_srv_url,
                     mail_from=mail_from,
                     mail_password=mail_password,
                     mail_to=mail_to,
                     mail_srv_port=mail_srv_port,
                     mail_srv_tls=True,
                     mail_subject="GlobalProtect Duplicate Sessions Detected",
                     mail_body=mail_body)
    else:
        log4y(f"PAN-OS API: Palo Alto NGFW {fw_ip} Not Reachable")

# Create Footer
log4y(f"{'#' * 20}\tGlobalProtect Logout Tool Finished\t{'#' * 20}")
