# Changes to be Made 

In dump.py Change the interface name to the one you want to capture packets on & by default it captures packets for 3mins change it as per your requirement.


## Let tcpdump capture packet without sudo

The following commands demonstrate the usage of the `pcap` snippet, which creates a group named `pcap` and modifies permissions for the `/usr/sbin/tcpdump` executable file.

1. Create the `pcap` group:
    ```
    groupadd pcap
    ```

2. Add the current user to the `pcap` group:
    ```
    usermod -a -G pcap $USER
    ```

3. Change the group ownership of `/usr/sbin/tcpdump` to `pcap`:
    ```
    chgrp pcap /usr/sbin/tcpdump
    ```

4. Set the permissions for `/usr/sbin/tcpdump` to `750`:
    ```
    chmod 750 /usr/sbin/tcpdump
    ```

5. Set the capabilities for `/usr/sbin/tcpdump` to `cap_net_raw` and `cap_net_admin`:
    ```
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
    ```

Please note that executing these commands requires administrative privileges (root access).
