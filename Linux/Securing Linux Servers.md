- Update software and system
- Update docker containers (use watchtower to auto update)

- Create a user other than root
    ```bash
    useradd username -m -s /bin/bash
    usermod -aG sudo,adm,docker username
    \#to add/change password
    passwd username 
    ```
    
- setup ssh keys
    
    ```bash
    \#in client machine
    ssh-keygen -b 4096 -C "some comments/ who this key is for" 
    # set up passphrase if needed
    
    \#to check 
    cd .ssh
    # id_rsa is private key. do not share this
    # id_rsa.pub is public key.
    
    # in server
    cd /home/username
    mkdir .ssh
    
    \#in client
    scp id_rsa.pub root@homeservername:/home/username/.ssh/authorised_keys \#give creds
    
    \#in server
    chown -R username:username .ssh
    ```
    
- Disable root login
    
    ```bash
    sudo nano /etc/ssh/sshd_config
    # change PermitRootLogin value from yes to no
    # to disable text password change PassworAuthentication to no
    
    # restart ssh to apply changes
    sudo systemctl restart ssh
    ```
    
- Control network IN and OUT
    
    ```bash
    \#get a list of all applications that are currently listening on network ports
    ss -ltpn
    \#go through all of them and find out if you really need them what are they for and what exactly are they doing
    \#all ip addresses with 0.0.0.0 are applications that are listening on all incoming interfaces
    \#port 80 for http, 443 for https and 22 for ssh
    ```
    
- Configure Firewall
    
    ```bash
    # allow ssh
    sudo ufw allow 22
    # to enable
    sudo ufw enable
    sudo ufw status
    
    \#not enough (eg: for docker)
    ```
    

- Use reverse proxy (eg: nginx proxy manager)

- Use an IPS (Intrusion Prevention System) eg: fail2ban
    
    ```bash
    sudo apt install fail2ban
    sudo systemctl enable fail2ban --now
    
    sudo systemctl status fail2ban
    \#for more info
    sudo fail2ban-client status
    \#jail list is just a collection of configuration files where you want to block specific ip addresses for services/ aka which service log it is looking in
    
    \#for service specific details
    sudo fail2ban-client status service \#eg: sshd
    ```
    
- Isolate applications with App armor
    
    - installed by default on ubuntu
    - it uses profiles for every application to determine which files and permissions the application requires
    
    ```bash
    \#see which profiles are currently running on your applications
    
    sudo apparmor_status
    # apps in the enforce mode are protected by app armor
    ```
    

---

> [!info] How to protect Linux from Hackers // My server security strategy!  
> How To Protect Linux From Hackers, Malware, and other bad things that could infect your server!  
> [https://youtu.be/Bx_HkLVBz9M](https://youtu.be/Bx_HkLVBz9M)