#!/usr/bin/python3
import smtplib
import datetime

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

mail_header = "Dear SoC Team;\n" \
              "Palo Alto Networks GlobalProtect Single Concurrent User Session Automation Tool has discovered duplicated sessions for below user accounts.\n\n"

mail_section_1 = "\nBelow details for users with duplicate sessions\n\n"

mail_trailer = "\nDuplicate sessions has been logout, only the first user session is kept-connected\n" \
               "\nRegards;\n" \
               "Palo Alto Networks Team"


def soc_mail_tls(mail_srv_add, mail_from, mail_password, mail_to, mail_srv_port="587", mail_subject="Subject", mail_body="Body"):
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