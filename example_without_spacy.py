#!/usr/bin/env python3

############
#
#   Escrito por ctw6av
#
#   Simples scanner de rede, parte de outro programa
#   que ainda esta em desenvolvimento, portanto não
#   possui versão.
#
#############

from socket import *
import sys


def recvall(sock, lenght):
    data = b''
    while len(data) < lenght:
        more = sock.recv(lenght - len(data))
        if not more:
            raise EOFError('was expecting %d bytes but only received'
                           '%d bytes before the socket' % (lenght, len(data)))
        data += more
    return data


def client(ip, port):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        try:
            sock.connect((ip, port))
            sock.sendto(b'Probing host')
            reply = recvall(sock, 16)
            print('The server said {}', repr(reply))
            sock.close()
        except timeout:
            pass
    except ConnectionRefusedError:
        print("host {} is up".format(ip))


def help():
    print('Usage: ./script [network]\nExiting')


if __name__ == '__main__':
    if len(sys.argv[:]) < 2:
        help()
    else:
        try:
            network = sys.argv[1].split('.')
            joined = '.'.join(network[0:3])
            print('Probing...')
            for i in range(1, 255):
                client(joined + '{}{}'.format('.', i), 1060)
            print('Done!')
        except KeyboardInterrupt:
            print('\rStoping...\n')