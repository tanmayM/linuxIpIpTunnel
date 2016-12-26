# linuxIpIpTunnel
Create a tunnel in netfilter hook

This code creates a ipip tunnel in netfilter POSTROUTING hook.
It sends the packet to a fixed proxy address. Address of the proxy
needs to be sent as a command line argument when the hook is loaded.
This can be done as follows:
insmod hookname proxyIpStr="1.2.3.4"
