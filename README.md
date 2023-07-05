# Triage
**Triage** is a firewall and router software solution that is designed to be installed on a  physical  
computer or virtual machine to provide dedicated firewall and routing  capabilities for a  
network. It includes a user-friendly web interface that allows for easy administration, even for  
users  with limited networking knowledge.

## Let tcpdump capture packet without sudo

The following commands demonstrate the usage of the `pcap` snippet, which creates a group named `pcap` and modifies permissions for the `/usr/sbin/tcpdump` executable file.

1.  Create the `pcap` group:
    
    ```
    groupadd triage
    ```
2.  Add the current user to the `triage` group:
    
    ```
    usermod -a -G triage $USER
    ```
3.  Change the group ownership of `/usr/sbin/iptables` to `triage`:
    
    ```
    chgrp triage /usr/sbin/iptables
    ```
4.  Set the permissions for `/usr/sbin/iptables` to `750`:

    ```
    chmod 750 /usr/sbin/iptables
    ```
5.  Add these lines to `sudoers list` make sure to change toymaker to your username:
    
    ```
    sudo visudo
    toymaker  ALL = NOPASSWD: /usr/sbin/iptables
    ```
Please note that executing these commands requires administrative privileges (root access).

## Screenshots


![Dashboard](https://raw.githubusercontent.com/Toymakerftw/adima/final/Screenshots/Screenshot%20from%202023-07-05%2022-01-52.png)
![Dashboard](https://raw.githubusercontent.com/Toymakerftw/adima/final/Screenshots/Screenshot%20from%202023-07-05%2022-10-10.png)
![Packet Details](https://raw.githubusercontent.com/Toymakerftw/adima/final/Screenshots/Screenshot%20from%202023-07-05%2022-10-20.png)
![Anomalous IP Addresses](https://raw.githubusercontent.com/Toymakerftw/adima/final/Screenshots/Screenshot%20from%202023-07-05%2022-10-32.png)
![Firewall](https://raw.githubusercontent.com/Toymakerftw/adima/final/Screenshots/Screenshot%20from%202023-07-05%2022-10-32.png)
