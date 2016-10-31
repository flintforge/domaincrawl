#!/usr/bin/python
# -*- coding: utf-8 -*-
"""

Continuous whois query from a dictionnary and log available domains.

author : Philippe Estival <phil.estival@free.fr>

usage: dns.py [-h] [--dom [dom]] [--ext [ext]] [--out [out]] [--line [line]]
              [--resume] [--session [session]]
              [dic]

positional arguments:
  dic                  dictionnary to load

optional arguments:
  -h, --help           show this help message and exit
  --dom [dom]          only check this domain
  --ext [ext]          TLD to check. Default=.com
  --out [out]          output file results
  --line [line]        starting line of dictionnary
  --resume             resume from last session
  --session [session]  session file


You can add a * star at any line in the dictionnary to force stop
when it's reached.

This script is distributed under the terms of the GPL v2 license.

"""

from subprocess import Popen, PIPE
import argparse
import re  # RegEx
from sys import stdout, exit

GREEN = "\033[1;32m"
NORMAL = "\033[0m"


class ShellCommand:
    def __init__(self, cmd=''):
        self.cmd = cmd
        self.output = ''
        self.returncode = -7
        self.errors = 0

    def run(self, cmd):
        try :
            print '-' * 40
            print 'running:', cmd
            p = Popen(cmd, stderr=PIPE, stdout=PIPE, shell=True)
            self.output, self.errors = p.communicate()
            if self.errors:
                print self.errors
                print 'something went wrong...'
                exit(1)
            self.returncode = p.returncode
            return self.returncode
        except KeyboardInterrupt:
            exit(0)


class DNSpy:
    def __init__(self,
                 dic,
                 lineNumber,
                 out,
                 session,
                 ext
                 ):
        self.dic = dic
        self.N = lineNumber
        self.out = out
        self.session = session

        print "Name of the file: ", self.session.name
        print "Closed or not : ", self.session.closed
        print "Opening mode : ", self.session.mode
        print "Softspace flag : ", self.dic.softspace
        print "resuming at line", self.N

        n = 0
        li = dic.readline().strip()
        while n in range(lineNumber - 2):
            n += 1
            li = self.dic.readline()
            if not li:
                self.eof = True
                break
            stdout.write(" %s\r" % li)

        li = li.strip()
        self.line = n
        com = ShellCommand()
        while li:
            dom = li + ext
            #cmd = '/bin/whois ' + li + '.com'
            cmd = 'whois -H ' + dom
            res = ''
            print self.N, " asking for ", dom
            com.run(cmd)
            # check what functions returns :
            # 2 : no net
            # 1 : not found
            # 0 : found
            print "returns: ", com.returncode

            # if self.error == 2:
            #    exit("problem")
            for line in com.output:
                res += line

            print com.output
            if re.search("(No match)|(No entries) ", com.output):
                print GREEN + dom + ' available!' + NORMAL
                self.out.write(dom + '\n')
                self.out.flush()
            else:
                print dom + ' taken'
                print res

            # +' | grep -e "No match" -e "No entries"'

            li = self.dic.readline()

            while not re.match('^[a-zA-Z0-9-]+$', li):
                if re.match('^.*\*.*$', li):
                    print 'matched star'
                    exit
                print "skipping", li
                li = self.dic.readline()
                self.N += 1

            li = li.strip()
            self.N += 1

    def start(self):
        self.dic.close()

    def __del__(self):

        print "exiting"
        print "saving to : " + self.session.name + " : " + str(self.N)

        self.session.seek(0)
        self.session.write(self.dic.name + ":" + str(self.N))
        self.session.truncate()
        self.session.close()
        self.dic.close()


def is_connected():
    try:
        host = socket.gethostbyname(REMOTE_SERVER)
        # connect to the host -- tells us if the host is actually
        # reachable
        socket.create_connection((host, 80), 2)
        return True
    except:
        pass
    return False


if __name__ == '__main__':

    if not is_connected():
        exit

    print ("\033[1;32m")
    print ("     ╔═══╗")
    print ("╔══╗ ║   ╝")
    print ("║  ╝ ║ Domaincrawl")
    print ("╚════╝\033[0m")

    parser = argparse.ArgumentParser(description='Continuous whois query from a dictionnary,\
        log available domains.')

    parser.add_argument('dic',
                        metavar='dic', type=file, nargs='?',
                        default='dictionnary.txt',
                        help='dictionnary to load')
    parser.add_argument('--dom',
                        metavar='dom', nargs='?',
                        help='only check this domain')
    parser.add_argument('--ext',
                        metavar='ext',
                        default='.com',
                        nargs='?', help='TLD to check. Default=.com')
    parser.add_argument('--out', metavar='out',
                        type=argparse.FileType('a'),
                        default='DN_AVAILABLES',
                        nargs='?',
                        help='output file results')
    parser.add_argument('--line', metavar='line', type=int,
                        default=0,
                        nargs='?',
                        help='starting line of dictionnary')
    parser.add_argument('--resume', action='store_true',
                        help='resume from last session')
    parser.add_argument('--session', metavar='session',
                        type=argparse.FileType('r+w'),
                        nargs='?',
                        default=open('session', 'r+w'),
                        help='session file')

    dic = 0
    line = int()

    args = parser.parse_args()

    # file session to save to
    #session= args.session if args.session else open('session','rw')

    if args.resume:
        save = args.session.readline().split(':')
        dic = open(save[0], 'r')
        line = int(save[1])

    else:
        # exit if(dic=None)
        print dic
        dic = args.dic
        line = int(args.line)

    print dic.name
    dnspy = DNSpy(dic, line, args.out, args.session, args.ext)


# eof
