#!/opt/http_log_analyzer/env/bin/python

'''
DESCR: parser for nginx access logs
AUTOR: Max Fedorov (mail@skam.in)
'''

import glob
import gzip
import os
import time
import sys
import datetime
import argparse
import curses
from subprocess import Popen, PIPE
import traceback
import yaml
import ipaddress
import logging
import netifaces
import threading
from logging.config import fileConfig
from logparser import Log

DAYS_INTERVAL = 1
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
TIMEZONE_OFFSET = 3.0  # Moscow Time (UTC+03:00)


class Config:
    def __init__(self, conf_path=None):
        self.access_log = Log(self)
        self.tailf = False
        self.path = None
        self.log = None
        self.start = None
        self.end = None
        self.request = None
        self.ip = None
        self.agent = None
        self.status = None
        self.geo = None
        self.resolve = True
        self.top_count = 10
        self.show_agent = False
        self.show_request = False
        self.show_ip = False
        self.show_slow_requests = False
        self.show_rps = False
        self.show_status = False
        self.show_geo = False
        self.update_interval = 1
        self.rps_interval = 1
        self.collect_interval = 5  # clear collected data every 5min
        self.collect_interval_last_ts = None
        self.runtime = None
        self.last_logs = []
        self.last_rps = 0
        self.start_ts = None
        self.close_ts = None
        self.scr = None
        self.stdscr = None
        self.stdscr_contents = ''
        self.max_rps = (0, '')
        self.quiet = False
        self.block = False
        self.block_demo = False
        self.blocked_list = []
        self.la_threshold = 0
        self.block_threshold_rps = 5
        self.block_threshold_ip = 300
        self.bad_user_agent_block_threshold_rps = None
        self.bad_dns_block_threshold_rps = None
        self.bad_dns = []
        self.bad_user_agent = []
        self.whitelist_requests = []
        self.whitelist_dns = []
        self.whitelist_ip = ['127.0.0.1']
        self.block_cmd = '''./iptctl.py --time 60 --add {ip}'''
        if os.path.exists(conf_path):
            self.parse(conf_path)
        else:
            error('File "{}" not found'.format(conf_path))
        self.exit = False

    def parse(self, path):
        with open(path, 'r') as stream:
            try:
                conf = yaml.safe_load(stream)
            except yaml.scanner.ScannerError as er:
                error('Fail to parse config file "{}"'.format(path))
                error(er)
                quit(0)

            if 'tailf' in conf:
                self.tailf = conf['tailf']
            if 'resolve' in conf:
                self.resolve = conf['resolve']
            if 'path' in conf:
                self.path = conf['path']
            if 'collect_interval' in conf:
                self.collect_interval = conf['collect_interval']
            if 'top_count' in conf:
                self.top_count = conf['top_count']

            if 'show_rps' in conf:
                self.show_rps = conf['show_rps']
            if 'show_ip' in conf:
                self.show_ip = conf['show_ip']
            if 'show_request' in conf:
                self.show_request = conf['show_request']
            if 'show_agent' in conf:
                self.show_agent = conf['show_agent']
            if 'show_status' in conf:
                self.show_status = conf['show_status']
            if 'show_slow_requests' in conf:
                self.show_slow_requests = conf['show_slow_requests']
            if 'show_geo' in conf:
                self.show_geo = conf['show_geo']

            if 'la_threshold' in conf:
                self.la_threshold = conf['la_threshold']
            if 'block_threshold_rps' in conf:
                self.block_threshold_rps = conf['block_threshold_rps']
            if 'block_threshold_ip' in conf:
                self.block_threshold_ip = conf['block_threshold_ip']
            if 'bad_user_agent_block_threshold_rps' in conf:
                self.bad_user_agent_block_threshold_rps = conf['bad_user_agent_block_threshold_rps']
            if 'bad_dns_block_threshold_rps' in conf:
                self.bad_dns_block_threshold_rps = conf['bad_dns_block_threshold_rps']

            if 'bad_user_agent' in conf:
                self.bad_user_agent = conf['bad_user_agent']
            if 'bad_dns' in conf:
                self.bad_dns = conf['bad_dns']
            if 'whitelist_dns' in conf:
                self.whitelist_dns = conf['whitelist_dns']
            if 'whitelist_requests' in conf:
                self.whitelist_requests = conf['whitelist_requests']
            if 'whitelist_ip' in conf:
                self.whitelist_ip = conf['whitelist_ip']
            if 'block_cmd' in conf:
                self.block_cmd = conf['block_cmd']
            if 'block' in conf:
                self.block = conf['block']
            if 'block_demo' in conf:
                self.block_demo = conf['block_demo']
            if 'quiet' in conf:
                self.quiet = conf['quiet']


class Tail(object):
    def __init__(self, tailed_file):
        self.check_file_validity(tailed_file)
        self.tailed_file = tailed_file
        self.callback = sys.stdout.write
        self.params = None

    def follow(self, s=1):
        with open(self.tailed_file) as file_:
            file_.seek(0, 2)
            while True:
                curr_position = file_.tell()
                line = file_.readline()
                if not line:
                    file_.seek(curr_position)
                    time.sleep(s)
                else:
                    self.callback(line)

    def register_callback(self, func):
        self.callback = func

    @staticmethod
    def check_file_validity(file_):
        if not os.access(file_, os.F_OK):
            raise TailError("File '%s' does not exist" % (file_))
        if not os.access(file_, os.R_OK):
            raise TailError("File '%s' not readable" % (file_))
        if os.path.isdir(file_):
            raise TailError("File '%s' is a directory" % (file_))


class TailError(Exception):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return self.message


def get_files(path):
    if type(path) is list:
        paths = sorted(path)
    else:
        paths = sorted(glob.glob(path))
    return paths


def block():
    while True:
        if params.la_threshold > round(os.getloadavg()[0], 3):
            return
        stat = [(params.access_log.rps[id].name, len(
            params.access_log.rps[id].requests)) for id in params.access_log.rps]
        for ip, count in sorted(stat, key=lambda kv: kv[1], reverse=True):
            if ip in params.blocked_list:
                continue
            cont = False
            for net in params.whitelist_ip:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    cont = True
                    break
            for d in params.whitelist_dns:
                if d in params.access_log.db_dns[ip]:
                    cont = True
                    break
            if cont:
                continue
            block_ip = False
            # block by bad dns
            if params.bad_dns_block_threshold_rps is not None and count >= params.bad_dns_block_threshold_rps:
                for d in params.bad_dns:
                    if d in params.access_log.db_dns[ip]:
                        block_ip = True
                        break
                if block_ip:
                    exec_block(ip, count, 'bad_dns', params)
                    del params.access_log.rps[ip]
                    continue
            # block by bad user agent
            if params.bad_user_agent_block_threshold_rps is not None and count >= params.bad_user_agent_block_threshold_rps:
                num = 0
                for r in params.access_log.rps[ip].requests:
                    req = params.access_log.all_requests[r]
                    ua = req.user_agent
                    for a in params.bad_user_agent:
                        if a in ua:
                            num += 1
                if num >= params.bad_user_agent_block_threshold_rps:
                    exec_block(ip, count, 'bad_user_agent', params)
                    del params.access_log.rps[ip]
                    continue
            if count >= params.block_threshold_rps:
                exec_block(ip, count, 'rps', params)
                del params.access_log.rps[ip]

        # block by ip count
        stat = [(params.access_log.ip[id].name, len(
            params.access_log.ip[id].requests)) for id in params.access_log.ip]
        for ip, count in sorted(stat, key=lambda kv: kv[1], reverse=True):
            if ip in params.blocked_list:
                continue
            cont = False
            for net in params.whitelist_ip:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    cont = True
                    break
            for d in params.whitelist_dns:
                if d in params.access_log.db_dns[ip]:
                    cont = True
                    break
            if cont:
                continue
            block_ip = False
            if not block_ip and count >= params.block_threshold_ip:
                exec_block(ip, count, 'ip', params)
                del params.access_log.ip[ip]
        if params.exit:
            return
        time.sleep(1)


def exec_block(ip, count, block_type, params):
    info('LA: {la} BLOCK by {t}:\t{v}\t{k}\t{g}\t({h})'.format(la=round(os.getloadavg()[0], 3),
                                                               k=ip, v=count, h=params.access_log.db_dns[ip],
                                                               t=block_type, g=params.access_log.db_geo[ip]))
    params.blocked_list.append(ip)

    if not params.block_demo:
        debug(params.block_cmd.format(ip=ip))
        r = Popen(params.block_cmd.format(ip=ip), shell=True,
                  stdout=PIPE, stderr=PIPE).communicate()
        debug(r)


def parse():
    threads = []
    if not params.quiet:
        thread_show_stat = threading.Thread(name="show_stat", target=show_stat, daemon=True)
        thread_show_stat.start()
        threads.append(thread_show_stat)
    if params.block or params.block_demo:
        thread_block = threading.Thread(name="block", target=block, daemon=True)
        thread_block.start()
        threads.append(thread_block)

    log_file = params.log
    if log_file.endswith(".gz"):
        logs = gzip.open(log_file).read()
        callback_parse_line(logs.decode("utf-8"))
    else:
        if params.tailf:
            t = Tail(log_file)
            t.register_callback(callback_parse_line)
            t.follow(s=params.update_interval)
        else:
            logs = open(log_file).read()
            callback_parse_line(logs)

    params.exit = True
    for thread in threads:
        thread.join()



def callback_parse_line(data):
    params.access_log.parse(data)


def show_stat():
    while True:
        if params.close_ts is None or params.start_ts is None: continue
        try:
            stat = generate_stat()
        except RuntimeError:
            continue
        height, width = params.scr.getmaxyx()
        stdscr = params.stdscr
        stdscr.clear()
        stdscr.scrollok(True)

        def stdscr_refresh():
            return stdscr.refresh(0, 0, 0, 0, height - 1, width)

        stdscr.addstr(stat)
        stdscr_refresh()
        params.stdscr_contents = stat
        if params.exit:
            return
        time.sleep(1)


def generate_stat():
    out = ''
    if params.ip is not None:
        out += 'Filtered by IP: {}\n'.format(params.ip)
    if params.request is not None:
        out += 'Filtered by REQUEST: "{}"\n'.format(params.request)
    if params.agent is not None:
        out += 'Filtered by USER_AGENT: "{}"\n'.format(params.agent)
    run_time = str(params.close_ts - params.start_ts).split('.')[0]
    out += 'Total requests: {t} || ' \
           'RPS last: {rs} max: {rm} || ' \
           'CPU LA: {la} || ' \
           'Run time: {rt} || ' \
           'Cur time: {dt}\n\n'.format(t=params.access_log.total,
                                       rs=params.last_rps,
                                       rt=run_time,
                                       rm=len(params.max_rps),
                                       dt=str(datetime.datetime.now()).split(
                                           '.')[0],
                                       la=[round(la, 3) for la in os.getloadavg()])
    if params.show_rps:
        out += '-' * 40 + '\nTOP {n} IP by RPS\n\n'.format(n=params.top_count)
        stat = [(params.access_log.rps[id].name, len(
            params.access_log.rps[id].requests)) for id in params.access_log.rps]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            if params.resolve:
                out += '{v}\t{k}\t({g})\t({h})\n'.format(k=name, v=count,
                                                         h=params.access_log.db_dns[name],
                                                         g=params.access_log.db_geo[name])
            else:
                out += '{v}\t{k}\t({g})\n'.format(k=name, v=count, g=params.access_log.db_geo[name])

    if params.show_ip:
        out += '-' * 40 + '\nTOP {n} by IP (Uniq {c}/{t})\n\n'.format(n=params.top_count,
                                                                      c=len(params.access_log.ip),
                                                                      t=params.access_log.total)
        stat = [(params.access_log.ip[id].name, len(
            params.access_log.ip[id].requests)) for id in params.access_log.ip]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            if params.resolve:
                out += '{v}\t{k}\t({g})\t({h})\n'.format(k=name, v=count,
                                                         h=params.access_log.db_dns[name],
                                                         g=params.access_log.db_geo[name])
            else:
                out += '{v}\t{k}\t({g})\n'.format(k=name, v=count, g=params.access_log.db_geo[name])

    if params.show_request:
        out += '-' * 40 + '\nTOP {n} by REQUEST (Uniq {c}/{t})\n\n'.format(
            n=params.top_count, c=len(params.access_log.request_url), t=params.access_log.total)
        stat = [(params.access_log.request_url[id].name, len(
            params.access_log.request_url[id].requests)) for id in params.access_log.request_url]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=name, v=count)

    if params.show_slow_requests:
        out += '-' * 40 + '\nTOP {n} by SLOW REQUESTS (Uniq {c}/{t})\n\n'.format(
            n=params.top_count, c=len(params.access_log.slow_request), t=params.access_log.total)
        stat = [(params.access_log.slow_request[id].name,
                 params.access_log.slow_request[id].time) for id in params.access_log.slow_request]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=name, v=count)

    if params.show_agent:
        out += '-' * 40 + '\nTOP {n} by USER_AGENT (Uniq {c}/{t})\n\n'.format(
            n=params.top_count, c=len(params.access_log.user_agent), t=params.access_log.total)
        stat = [(params.access_log.user_agent[id].name, len(
            params.access_log.user_agent[id].requests)) for id in params.access_log.user_agent]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=name, v=count)

    if params.show_status:
        out += '-' * 40 + '\nTOP {n} by STATUS\n\n'.format(n=params.top_count)
        stat = [(params.access_log.status_code[id].name, len(
            params.access_log.status_code[id].requests)) for id in params.access_log.status_code]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=name, v=count)

    if params.show_geo:
        out += '-' * 40 + '\nTOP {n} by GEO\n\n'.format(n=params.top_count)
        stat = [(params.access_log.geo[id].name, len(
            params.access_log.geo[id].requests)) for id in params.access_log.geo]
        for name, count in sorted(stat, key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=name, v=count)

    return out


def get_local_ips():
    ips = [netifaces.ifaddresses(intf).setdefault(netifaces.AF_INET)[0]['addr']
           for intf in netifaces.interfaces() if netifaces.ifaddresses(intf).setdefault(netifaces.AF_INET)]
    return ips


def main(scr=None):
    if not params.quiet:
        scr.keypad(True)
        curses.noecho()
        height, width = scr.getmaxyx()
        scr.refresh()
        scr.clear()
        stdscr = curses.newpad(height + 100, width)
        params.stdscr = stdscr
        params.scr = scr

    local_ips = get_local_ips()
    if len(local_ips):
        params.whitelist_ip.extend(local_ips)
    params.whitelist_ip = list(set(params.whitelist_ip))
    if params.path is None:
        error('Bad value for argument --path : "{}"'.format(params.path))
        quit(0)
    debug('WHITELIST_IPS: {}'.format(params.whitelist_ip))
    for f in get_files(params.path):
        params.log = f
        parse()


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    fileConfig('logging.ini')
    logger = logging.getLogger(__name__)
    error = logger.error
    debug = logger.debug
    info = logger.info
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=TIMEZONE_OFFSET)
    now_minus_24 = now - datetime.timedelta(hours=24)
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, help='path to config file (default is ".http_log_analyzer.yml")',
                        default='.http_log_analyzer.yml')
    parser.add_argument('--path', nargs='+', type=str,
                        help="Path to access log file")
    parser.add_argument('-f', dest="tailf",
                        help="tail -f mode", action="store_true")
    parser.add_argument('--start', '-s', type=str,
                        help="start time in format '{}'".format(now_minus_24.strftime(TIME_FORMAT)))
    parser.add_argument('--end', '-e', type=str,
                        help="end time in format '{}'".format(now.strftime(TIME_FORMAT)))
    parser.add_argument('--req', type=str, help="filter by request")
    parser.add_argument('--ip', type=str, help="filter by ip")
    parser.add_argument('--agent', type=str, help="filter by user_agent")
    parser.add_argument('--status', type=str, help="filter by status code")
    parser.add_argument('--geo', type=str, help="filter by country")

    parser.add_argument(
        '--show', nargs='+', help='Which type of TOP to show: "rps", "ip", "req", "agent", "status", "slow", "geo"')
    parser.add_argument('--count', dest='top_count',
                        type=int, help="Number of TOP records")
    parser.add_argument('--no-resolve', dest="resolve",
                        help="Don't resolve IPs to hostnames", action="store_true")
    parser.add_argument('--quiet', '-q', dest="quiet",
                        help="Run in non interactive mode(show only blocked IPs)", action="store_true")
    parser.add_argument(
        '--block', help="Block top IPs in iptables", action="store_true")
    parser.add_argument('--block-demo', dest="block_demo",
                        help="Not block IPs, only show", action="store_true")
    parser.add_argument('--interval', '-i', type=int,
                        help="Collect data interval in minutes (Default is 5)")

    args = parser.parse_args()

    params = Config(args.config)

    if args.show is not None:
        if 'ip' in args.show:
            params.show_ip = True
        else:
            params.show_ip = False
        if 'req' in args.show:
            params.show_request = True
        else:
            params.show_request = False
        if 'agent' in args.show:
            params.show_agent = True
        else:
            params.show_agent = False
        if 'slow' in args.show:
            params.show_slow_requests = True
        else:
            params.show_slow_requests = False
        if 'rps' in args.show:
            params.show_rps = True
        else:
            params.show_rps = False
        if 'status' in args.show:
            params.show_status = True
        else:
            params.show_status = False
        if 'geo' in args.show:
            params.show_geo = True
        else:
            params.show_geo = False

    if args.start:
        try:
            params.start = datetime.datetime.strptime(args.start, TIME_FORMAT)
        except ValueError:
            error('Bad time format')
            parser.print_help(sys.stderr)
            quit(0)
    else:
        params.start = now - datetime.timedelta(hours=24)
    if args.end:
        try:
            params.end = datetime.datetime.strptime(args.end, TIME_FORMAT)
        except ValueError:
            error('Bad time format')
            parser.print_help(sys.stderr)
            quit(0)

    if args.interval:
        params.collect_interval = args.interval
    if args.quiet:
        params.quiet = args.quiet
    if args.block:
        params.block = args.block
    if args.block_demo:
        params.block_demo = args.block_demo
    if args.path:
        params.path = args.path
    if args.top_count:
        params.top_count = args.top_count
    if args.tailf:
        params.tailf = True
    if args.req:
        params.request = args.req
    if args.ip:
        params.ip = args.ip
    if args.agent:
        params.agent = args.agent
    if args.status:
        params.status = args.status
    if args.geo:
        params.geo = args.geo
    if args.resolve:
        params.resolve = False

    try:
        if not params.quiet:
            curses.wrapper(main)
        else:
            main()
    except KeyboardInterrupt:
        pass
    except Exception as er:
        debug(traceback.format_exc())
        error(er)
    finally:
        for line in params.stdscr_contents.splitlines():
            info('{}\r'.format(line))
