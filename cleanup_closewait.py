#!/usr/bin/python
# coding: utf-8
"""
The script will close all in the half-close state of the client socket connection,
only support UNIX/LINUX.

command: cleanup_closewait -s --server ipaddr:port [-c --client ipaddr:port]
                           --all
                           -h --help

-----------------------
TCP Protocol operation:
https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Protocol_operation

VERSION: 1.0 2016-10-15
AUTHOR: william
"""
import socket
import sys
import subprocess
import getopt
from struct import *


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:c:h', ['all', 'help', 'server=', 'client='])

        server = ''
        client = ''

        for opt, arg in opts:
            if opt in ('-s', '--server'):
                server = arg.strip()
            if opt in ('-c', '--client'):
                client = arg.strip()
            if opt in ('-h', '--help'):
                help()
            if opt == '--all':
                cleanup_all_closewait()

        if len(server) != 0 or len(client) != 0:
            cleanup_closewait(server, client)

    except getopt.GetoptError:
        pass


def find_closewait(shell):
    handle = subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE)
    return handle.communicate()[0]


def cleanup(result=''):
    socketcli = SocketUtil()

    try:
        if result is None or len(result.strip()) == 0:
            print 'No CLOSE_WAIT found, Goodbye :)'
            sys.exit(0)
        arr = result.strip().split('\n')
        print '* Find %s CLOSE_WAIT status...' % len(arr)
        print '* Send data packets to them...'

        for tmp in arr:
            target = tmp.strip().split(' ')
            # print target
            dest_host = target[0].split(':')  # client side
            src_host = target[1].split(':')  # server side
            #
            socketcli.finack(
                src_ip=src_host[0],
                src_port=int(src_host[1]),
                dest_ip=dest_host[0],
                dest_port=int(dest_host[1])
            )
            # print '%s:%s -> %s:%s' % (str(dest_host[0]), str(dest_host[1]), str(src_host[0]), str(src_host[1]))

        print '* The job was completed, all CLOSE_WAIT has been closed.'
    finally:
        socketcli.close()


def cleanup_closewait(server=None, client=None):
    awk_code = "| awk '{print $4,$5}' | sed 's/ ::ffff:/ /g' | sed 's/::ffff:/ /g'"
    netstat_code = "netstat -na | grep CLOSE_WAIT {0} {1} {2}"

    if len(server) != 0 and server.find(':') != -1:
        server = '| grep %s' % server.strip()
    else:
        server = ''
    if len(client) != 0 and client.find(':') != -1:
        client = '| grep %s' % client.strip()
    else:
        client = ''

    shell_ex = netstat_code.format(server, client, awk_code)

    cleanup(find_closewait(shell_ex))


def cleanup_all_closewait():
    shell_ex = "netstat -na | grep CLOSE_WAIT | awk '{print $4,$5}' | sed 's/ ::ffff:/ /g' | sed 's/::ffff:/ /g'"
    cleanup(find_closewait(shell_ex))


def help():
    print 'Usage: python cleanup_closewait -h'
    print 'v1.0.1 20161016 @w'
    print '----------------------------------------'
    print '-s ip:port, --server=ip:port'
    print '-c ip:port, --client=ip:port'
    print '--all\t\t\tcleanup all CLOSE_WAIT status.'
    print '-h, --help\t\tdisplay this help and exit.\n'
    sys.exit()


class SocketUtil:
    """ Socket util """

    def __init__(self):
        try:
            self.socketCli = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error, msg:
            print 'Socket could not be created. error code : %s message %s' % (msg[0], msg[1])
            sys.exit(1)

    def finack(self, src_ip, src_port, dest_ip, dest_port):
        """ send a FIN&ACK packet to the target host, return TRUE/FALSE """
        packet = FinAckPacketUtil().packet(src_ip, src_port, dest_ip, dest_port)
        lens = self.socketCli.sendto(packet, (dest_ip, dest_port))
        return lens > 0

    def close(self):
        """ release the socket connection """
        if self.socketCli is not None:
            self.socketCli.close()


class FinAckPacketUtil:
    """ a TCP FIN&ACK packet util """

    def __init__(self):
        self._tcp_seq = 10
        self._tcp_ack_seq = 66
        self._tcp_doff = 5
        # tcp flags
        self._tcp_fin = 1
        self._tcp_syn = 0
        self._tcp_rst = 0
        self._tcp_psh = 0
        self._tcp_ack = 1
        self._tcp_urg = 0
        self._tcp_window = socket.htons(128)
        self._tcp_check = 0
        self._tcp_urg_ptr = 0
        #
        self._tcp_offset_res = (self._tcp_doff << 4) + 0
        self._tcp_flags = self._tcp_fin + (self._tcp_syn << 1) + (self._tcp_rst << 2) + (self._tcp_psh << 3) + (
            self._tcp_ack << 4) + (self._tcp_urg << 5)

    def __checksum(self, msg):
        sm = 0

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            sm = (sm + w)

        sm = (sm >> 16) + (sm & 0xffff)
        sm = (sm + (sm >> 16))

        # complement and mask to 4 byte short
        sm = ~sm & 0xffff

        return sm

    def __ipheader(self, src_ip='127.0.0.1', dest_ip='127.0.0.1'):
        """  create a ip header of the TCP packet """
        ip_ihl = 5  # header length
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0
        ip_id = 2345  # packet id
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        ip_header = pack('!BBHHHBBH4s4s',
                         ip_ihl_ver,
                         ip_tos,
                         ip_tot_len,
                         ip_id,
                         ip_frag_off,
                         ip_ttl,
                         ip_proto,
                         ip_check,
                         ip_saddr,
                         ip_daddr)

        return ip_header

    def packet(self, src_ip='127.0.0.1', src_port=8080, dest_ip='127.0.0.1', dest_port=8080):
        """ create a TCP packet """
        tcp_header = pack('!HHLLBBHHH', src_port,
                          dest_port,
                          self._tcp_seq,
                          self._tcp_ack_seq,
                          self._tcp_offset_res,
                          self._tcp_flags,
                          self._tcp_window,
                          self._tcp_check,
                          self._tcp_urg_ptr)

        psh = pack('!4s4sBBH', socket.inet_aton(src_ip),
                   socket.inet_aton(dest_ip), 0, socket.IPPROTO_TCP, len(tcp_header))
        psh = (psh + tcp_header)
        check_code = pack('H', self.__checksum(psh))
        urg_code = pack('!H', self._tcp_urg_ptr)

        tcp_header = pack('!HHLLBBH',
                          src_port,
                          dest_port,
                          self._tcp_seq,
                          self._tcp_ack_seq,
                          self._tcp_offset_res,
                          self._tcp_flags,
                          self._tcp_window) + check_code + urg_code

        packet = self.__ipheader(src_ip, dest_ip) + tcp_header

        return packet


if __name__ == '__main__':
    main()
