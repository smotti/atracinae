#!/usr/bin/env python2

# Atracinae is the group name for australian funnel-web spiders

from logging import getLogger, Formatter, StreamHandler, INFO
from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket
from sys import exit


conf.verbose = 0
conf.L3socket = L3RawSocket


LOG_FMT = '%(levelname)s %(asctime)s %(name)s %(filename)s:%(lineno)d %(message)s'
LOG_DATEFMT = '%Y-%m-%dT%H:%M:%SZ'

LOGGER = getLogger('atracinae')
stdout = StreamHandler()
stdout.setFormatter(Formatter(LOG_FMT, LOG_DATEFMT))
stdout.setLevel(INFO)
LOGGER.setLevel(INFO)
LOGGER.addHandler(stdout)


def sendIcmpReply(pkt):
    ip = IP()
    icmp = ICMP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    icmp.type = 0
    icmp.code = 0
    icmp.id = pkt[ICMP].id
    icmp.seq = pkt[ICMP].seq
    LOGGER.info('Send ICMP reply to {}'.format(ip.dst))
    data = pkt[ICMP].payload
    send(ip/icmp/data, verbose=0)


def handlePacket(pkt):
    data = pkt.get_payload()
    scapyPkt = IP(data)
    proto = scapyPkt.proto

    pkt.drop()

    if proto is 0x01:
        LOGGER.info('Intercepted ICMP packet from {}'.format(scapyPkt[IP].src))
        if scapyPkt[ICMP].type is 8:
            sendIcmpReply(scapyPkt)
        else:
            pass


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, handlePacket)
    s = socket.fromfd(nfqueue.get_fd(), socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
#        nfqueue.run()
        nfqueue.run_socket(s)
    except KeyboardInterrupt as e:
        raise e
    finally:
        nfqueue.unbind()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
    except Exception as e:
        LOGGER.error(str(e))
        exit(1)
