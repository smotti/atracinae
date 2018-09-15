# Description

A small tool to intercept ICMP echo packets and forging a response for them.

# Dependencies

* Python 2.x (for atracinae)
* Python modules (python 2.x)
  * scapy (to forge our own ICMP packets)
  * netfilterqueue (required libnetfilter\_queue)
* IPTABLES NFQUEUE support (implies you have linux, this is required to test
  the pinging without real hosts)
* libnetfilter\_queue (see prev item why)

# Usage

## Ping

To test the connectivity with simulated hosts in a specific subnet (i.e.
192.168.100.0/24) you have to add an iptables rule:

```
# iptables -A OUTPUT -p icmp --destination 192.168.100.0/24 -j NFQUEUE
```

Now you can run atracinae which intercepts the ICMP echo packets and sends
a forged reply:

```
$ sudo -E ./atracinae.py
```

When atracinae is running you can send ICMP echo packets via the ping utility
to any host in the subnet, as specified in the iptables rules, and you'll
receive a proper reply.
