Clone the code in you machine in dir $dir_name

    git clone https://github.com/ysaied/gp_logout_tool.git $dir_name

Keep the Code up-to-date    

    cd $dir_name
    git pull

Modify the "secrets.txt" file with your system parameters. Move the file to secure place

    FW_IP=$FW_IP
    FW_UNAME=$FW_Username
    FW_PWD=$FW_Password
    MAIL_SRV_TYPE=${tls|cleartext}
    MAIL_SRV_URL=$MAIL_Server_IP/URL
    MAIL_SRV_Port=$MAIL_Server_Port
    MAIL_FROM=$MAIL_Account_ID
    MAIL_PWD=$MAIL_Account_Password
    MAIL_TO=$SEN_TO_EMAIL
    CSV_Dir=$CSV_Directory_Path

    
In main.py, replace the secrets file path, with your secrets file absolute path
    
    credentials = get_secrets($Secrets_file_absolute_path)
