#!/usr/bin/python3
import smtplib
import datetime
# from prettytable import PrettyTable

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

mail_header = "Dear SoC Team;\n" \
              "Palo Alto Networks GlobalProtect Single Concurrent User Session Automation Tool has discovered duplicated sessions for below user accounts.\n\n"

mail_section_1 = "\nBelow details for users with duplicate sessions\n\n"

mail_trailer = "\nDuplicate sessions has been logout, only the first user session is kept-connected\n" \
               "\nRegards;\n" \
               "Palo Alto Networks Team"


def soc_mail_tls(mail_srv_add, mail_from, mail_password, mail_to, mail_srv_port="587", mail_subject="Subject",
                 mail_body="Body"):
    try:
        log4y(f"SoC Email: Check for Server {mail_srv_add}:{mail_srv_port}")
        mail_server = smtplib.SMTP(mail_srv_add, mail_srv_port)
    except:
        log4y(f"SoC Email: Server Connection Error, {mail_srv_add}:{mail_srv_port} Unreachable")
        log4y(f"SoC Email: Skip Sending Email to SoC team")
        return False
    else:
        log4y(f"SoC Email: Server {mail_srv_add}:{mail_srv_port} Found")

    try:
        log4y(f"SoC Email: Request TLS/SSL Connection with Server {mail_srv_add}:{mail_srv_port}")
        mail_server.starttls()
    except:
        log4y(f"SoC Email: TLS/SSL Connection Error, Server {mail_srv_add} Untrusted Certificate")
        log4y(f"SoC Email: Skip Sending Email to SoC team")
        return False
    else:
        log4y(f"SoC Email: TLS/SSL Connection Established with Mail {mail_srv_add}:{mail_srv_port}")

    try:
        log4y(f"SoC Email: Request Account Login for {mail_from} on Server {mail_srv_add}")
        mail_server.login(mail_from, mail_password)
    except:
        log4y(f"SoC Email: Account Login Failure for {mail_from}, Credentials Error")
        log4y(f"SoC Email: Skip Sending Email to SoC team")
        return False
    else:
        log4y(f"SoC Email: Account Login Success for {mail_from} on Server {mail_srv_add}")
        mail_msg = f"Subject: {mail_subject}\n\n{mail_body}"
        mail_server.sendmail(from_addr=mail_from, to_addrs=mail_to, msg=mail_msg)
        log4y(f"SoC Email: Email Sent Successfully")
        mail_server.quit()
        return True


def soc_mail_cleartext(mail_srv_add, mail_from, mail_to, mail_srv_port="25", mail_subject="Subject", mail_body="Body"):
    try:
        log4y(f"SoC Email: Check for Server {mail_srv_add}:{mail_srv_port}")
        mail_server = smtplib.SMTP(mail_srv_add, mail_srv_port)
    except:
        log4y(f"SoC Email: Server Connection Error, {mail_srv_add}:{mail_srv_port} Unreachable")
        log4y(f"SoC Email: Skip Sending Email to SoC team")
        return False
    else:
        log4y(f"SoC Email: Server {mail_srv_add}:{mail_srv_port} Found")

    try:
        log4y(f"SoC Email: Email Sent Request from:{mail_from} to:{mail_to} server:{mail_server}:{mail_srv_port}")
        mail_msg = f"Subject: {mail_subject}\n\n{mail_body}"
        mail_server.sendmail(from_addr=mail_from, to_addrs=mail_to, msg=mail_msg)
    except:
        log4y(f"SoC Email: Email Sent Failure")
        log4y(f"SoC Email: Skip Sending Email to SoC team")
        return False
    else:
        log4y(f"SoC Email: Email Sent Successfully")
        mail_server.quit()
        return True


def soc_mail(mail_srv_add,
             mail_from,
             mail_to, mail_password,
             mail_srv_port,
             mail_subject="Subject",
             mail_body="Body",
             mail_srv_typ="tls"
             ):
    if mail_srv_typ == "tls":
        log4y(f"SoC Email: TLS/SMTP Email Option Selected")
        soc_mail_tls(mail_srv_add, mail_from, mail_password, mail_to, mail_srv_port, mail_subject, mail_body)
    elif mail_srv_typ == "cleartext":
        log4y(f"SoC Email: Clear-Text SMTP  Email Option Selected")
        soc_mail_cleartext(mail_srv_add, mail_from, mail_to, mail_srv_port, mail_subject, mail_body)
    else:
        log4y(f"SoC Email: Empty or Wrong SMTP  Email Option Selected")
        log4y(f"SoC Email: Skip Sending Email to SoC team")


def soc_mail_body(gp_duplicate_lst, gp_duplicate_ext):
    users_list = f"Username\n"
    for _ in gp_duplicate_lst:
        users_list += f"{_}\n"
    user_ext_data = str()
    for _ in gp_duplicate_ext:
        user_ext_header = str()
        for key, value in _.items():
            user_ext_header += f"{key}\t\t"
            user_ext_data += f"{value}\t\t"
        user_ext_header += f"\n"
        user_ext_data += f"\n"

    mail_body = f"{mail_header}{users_list}\n{mail_section_1}{user_ext_header}{user_ext_data}\n{mail_trailer}"
    return mail_body

# def soc_mail_body_table(gp_duplicate_lst, gp_duplicate_ext):
#     summary_table = PrettyTable()
#     extended_table = PrettyTable()
#
#     # Generate Rows for Summary Table
#     summary_table.field_names = ["Username"]
#     for _ in gp_duplicate_lst:
#         summary_table.add_row([_])
#     # Generate Rows for Extended Table
#     for _ in gp_duplicate_ext:
#         header = []
#         row = []
#         for key, value in _.items():
#             header.append(key)
#             row.append(value)
#         extended_table.add_row(row)
#     extended_table.field_names = header
#
#     mail_body = f"{mail_header}{summary_table}\n{mail_section_1}{extended_table}\n{mail_trailer}"
#     return mail_body
