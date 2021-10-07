#!/opt/http_log_analyzer/env/bin/python

'''
DESCR: This tool allow block IP in iptables and set timeout. When timeout is come - remove block rule.
AUTOR: Max Fedorov (mail@skam.in)
'''

import iptc
import datetime
import argparse
import traceback
import os
import ipaddress

WHITE_LIST = ['127.0.0.1']


class Config():
    def __init__(self):
        self.whitelist = WHITE_LIST
        self.block_time_in_min = 60
        self.blocked_ips = []
        self.ip = None
        self.rule_insert_position = 0
        self.action = None


def create_rule(params):
    ip = params.ip
    if ip in WHITE_LIST:
        print('SKIPPED: {} in whitelist'.format(ip))
        return None
    print('ADD block for {}'.format(ip))
    rule = iptc.Rule()
    rule.src = ip
    rule.protocol = "tcp"
    match = rule.create_match('tcp')
    #match = rule.create_match('multiport')
    #match.dports = '80,443'
    match = rule.create_match("comment")
    ts = int(datetime.datetime.timestamp(datetime.datetime.now() +
             datetime.timedelta(minutes=params.block_time_in_min)))
    match.comment = 'http_access_log_block:{}'.format(ts)
    rule.create_target("REJECT")
    return rule


def update_rules(params):
    table = iptc.Table(iptc.Table.FILTER)
    table.autocommit = False
    chain = iptc.Chain(table, "INPUT")
    need_commit = False
    for rule in chain.rules:
        for m in rule.matches:
            # print(iptc.easy.decode_iptc_rule(rule))
            if m.name == 'comment' and m.comment.startswith('http_access_log_block'):
                # print(iptc.easy.decode_iptc_rule(rule))
                m_ip = rule.src.split('/')[0]
                m_ip_ts = datetime.datetime.fromtimestamp(
                    float(m.comment.split(':')[1]))
                if params.action == 'delall':
                    print('FORCE Deleting ip {}'.format(m_ip))
                    chain.delete_rule(rule)
                    need_commit = True
                    continue
                if params.action == 'del' and m_ip == params.ip:
                    print('FORCE Deleting ip {}'.format(m_ip))
                    chain.delete_rule(rule)
                    need_commit = True
                    continue
                if params.action == 'list':
                    print('{}'.format(m_ip))
                if datetime.datetime.now() >= m_ip_ts:
                    print('BLOCK TIMEOUT for ip {}'.format(m_ip))
                    chain.delete_rule(rule)
                    need_commit = True
                    continue
                params.blocked_ips.append(m_ip)

    # print(params.blocked_ips)
    # quit(0)
    if params.ip not in params.blocked_ips and params.action == 'add':
        rule = create_rule(params)
        if rule is not None:
            chain.insert_rule(rule, position=params.rule_insert_position)
            need_commit = True
            params.blocked_ips.append(params.ip)

    if need_commit:
        table.commit()


def main():
    params = Config()
    parser = argparse.ArgumentParser()
    parser.add_argument('--add', '-a', type=str,
                        help='IP for adding to iptables block')
    parser.add_argument('--time', '-t', default=60, type=int,
                        help='Time in minutes for block IP with --add option (default is 60)')
    parser.add_argument('--del', '-d', dest='remove', type=str,
                        help='IP for deleting from iptables block')
    parser.add_argument('--delall', default=False,
                        action='store_true', help='Clear all blocked IPs')
    parser.add_argument('--list', '-l', default=False,
                        action='store_true', help='Show list of blocked ip')

    args, unknown_args = parser.parse_known_args()
    if args.add:
        params.ip = args.add
        params.action = 'add'
    if args.remove:
        params.ip = args.remove
        params.action = 'del'
    if args.list:
        params.action = 'list'
    if args.delall:
        params.action = 'delall'
    params.block_time_in_min = args.time
    if params.ip is not None:
        try:
            ipaddress.ip_address(params.ip)
        except ValueError:
            print('ERROR: BAD IP')
            quit(0)

    update_rules(params)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    try:
        main()
    except KeyboardInterrupt:
        print('Aborted')
    except Exception as error:
        print(traceback.format_exc())
        print(error)
