# gp_logout_tool

Code files to be copied
    main.py
    pan_fw.py
    soc_mail.py

Secrets file to be placed in secure place with below format
    FW_IP=$FW_IP
    FW_UNAME=$FW_Username
    FW_PWD=$FW_Password
    MAIL_SRV_URL=$MAIL_Server_IP/URL
    MAIL_SRV_Port=$MAIL_Server_Port
    MAIL_FROM=$MAIL_Account_ID
    MAIL_PWD=$MAIL_Account_Password
    MAIL_TO=$SEN_TO_EMAIL
    CSV_Dir=$CSV_Directory_Path
    
In main.py, replace the secrets file path, with your secrets file absolute path
    credentials = get_secrets($Secrets_file_absolute_path)
