#!/opt/http_log_analyzer/env/bin/python


'''
DESCR: parser for nginx access logs
AUTOR: Max Fedorov (mail@skam.in)
'''

import glob
import gzip
import re
import os
import time
import sys
import datetime
import argparse
import socket
import collections
import curses
from subprocess import Popen, PIPE
import traceback
import yaml
import logging
from logging.config import fileConfig
from geoip import geo

DAYS_INTERVAL = 1
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
TIMEZONE_OFFSET = 3.0  # Moscow Time (UTC+03:00)

STAT = {'ip': {},
        'request': {},
        'host': {},
        'useragent': {},
        'rps_ip': {},
        'total': 0,
        'request_time': {},
        'status': {}}
DNS = {}

log_format = re.compile(r'''(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'''
                        r'''-\s+'''
                        r'''(?P<user>.*?)\s+'''
                        r'''\[(?P<datetime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+(\+|\-)\d{4})\]\s+'''
                        r'''(\"(?P<request>.*?)\")\s+'''
                        r'''(?P<status>\d{3})\s+'''
                        r'''(?P<bytessent>\d+)\s+'''
                        r'''(\"(?P<referrer>.*?)\")\s+'''
                        r'''(\"(?P<useragent>.*?)\")\s+'''
                        r'''(?P<upstream>.*?)\s+'''
                        r'''(?P<upstream_response_time>.*?)\s+'''
                        r'''(?P<request_time>.*?)\s+'''
                        r'''(?P<host>.*?)$''', re.IGNORECASE | re.VERBOSE)


class Config():
    def __init__(self, conf_path=None):
        self.tailf = False
        self.path = None
        self.log = None
        self.start = None
        self.end = None
        self.request = None
        self.ip = None
        self.agent = None
        self.status = None
        self.resolve = True
        self.top_count = 10
        self.show_agent = False
        self.show_request = False
        self.show_ip = False
        self.show_slow_requests = False
        self.show_rps = False
        self.show_status = False
        self.update_interval = 1
        self.rps_interval = 1
        self.collect_interval = 5  # clear collected data every 5min
        self.collect_interval_last_ts = None
        self.logs = []
        self.runtime = None
        self.last_logs = []
        self.last_rps = 0
        self.start_ts = None
        self.close_ts = None
        self.scr = None
        self.stdscr = None
        self.stdscr_contents = ''
        self.max_rps = (0, '')
        self.block = False
        self.block_demo = False
        self.blocked_list = []
        self.block_threshold_rps = 5
        self.block_threshold_ip = 300
        self.bad_user_agent_block_threshold_rps = None
        self.bad_dns_block_threshold_rps = None
        self.whitelist_requests = []
        self.bad_dns = []
        self.bad_user_agent = []
        self.whitelist_dns = []
        self.block_cmd = '''./iptctl.py --time 60 --add {ip}'''
        if os.path.exists(conf_path):
            self.parse(conf_path)
        else:
            error('File "{}" not found'.format(conf_path))

    def parse(self, path):
        with open(path, 'r') as stream:
            conf = yaml.safe_load(stream)
            if 'tailf' in conf:
                self.tailf = conf['tailf']
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
                    self.callback(line, self.params)

    def register_callback(self, func, params):
        self.callback = func
        self.params = params

    def check_file_validity(self, file_):
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


def calc_rps_top(logs):
    for ip, count in collections.Counter(logs).most_common():
        if ip in STAT['rps_ip']:
            if count > STAT['rps_ip'][ip]:
                STAT['rps_ip'][ip] = count
        else:
            STAT['rps_ip'][ip] = count


def block(params):
    # block by rps count
    for ip, count in sorted(STAT['rps_ip'].items(), key=lambda kv: kv[1], reverse=True):
        if ip in params.blocked_list:
            continue
        if ip not in DNS:
            DNS[ip] = socket.getfqdn(ip)
        block_ip = False
        if params.bad_dns_block_threshold_rps is not None and count >= params.bad_dns_block_threshold_rps:
            for d in params.bad_dns:
                if d in DNS[ip]:
                    block_ip = True
                    break
        if not block_ip and count >= params.block_threshold_rps:
            cont = False
            for d in params.whitelist_dns:
                if d in DNS[ip]:
                    cont = True
                    break
            if cont:
                continue

        if block_ip:
            exec_block(ip, count, 'rps', params)
            del STAT['rps_ip'][ip]

    # block by ip count
    for ip, count in sorted(STAT['ip'].items(), key=lambda kv: kv[1], reverse=True):
        if ip in params.blocked_list:
            continue
        if ip not in DNS:
            DNS[ip] = socket.getfqdn(ip)
        block_ip = False
        
        if not block_ip and count >= params.block_threshold_ip:
            cont = False
            for d in params.whitelist_dns:
                if d in DNS[ip]:
                    cont = True
                    break
            if cont:
                continue

        if block_ip:
            exec_block(ip, count, 'ip', params)
            del STAT['ip'][ip]


def exec_block(ip, count, block_type, params):
    now = str(datetime.datetime.now()).split('.')[0]
    debug(generate_stat(params))
    info('{n} BLOCK by {t}: {v}\t{k}\t({h})'.format(
        k=ip, v=count, h=DNS[ip], n=now, t=block_type))
    params.blocked_list.append(ip)

    if not params.block_demo:
        debug(params.block_cmd.format(ip=ip))
        r = Popen(params.block_cmd.format(ip=ip), shell=True,
                  stdout=PIPE, stderr=PIPE).communicate()
        debug(r)


def parse(params):
    log_file = params.log
    if log_file.endswith(".gz"):
        logs = gzip.open(log_file).read()
        callback_parse_line(logs.decode("utf-8"), params)
    else:
        if params.tailf:
            t = Tail(log_file)
            t.register_callback(callback_parse_line, params)
            t.follow(s=params.update_interval)
        else:
            logs = open(log_file).read()
            callback_parse_line(logs, params)


def callback_parse_line(data, params):
    for l in data.splitlines():
        data = re.search(log_format, l)
        if data:
            datadict = data.groupdict()
            ip = datadict['ip']
            request = datadict['request']
            bytessent = datadict['bytessent']
            referrer = datadict['referrer']
            useragent = datadict['useragent']
            status = datadict['status']
            host = datadict['host']
            request_time = datadict['request_time']
            datetimestring = datadict['datetime']
            dt = datetime.datetime.strptime(
                datetimestring.split()[0], '%d/%b/%Y:%H:%M:%S')
            if params.collect_interval_last_ts is None:
                params.collect_interval_last_ts = dt
            if dt - params.collect_interval_last_ts >= datetime.timedelta(minutes=params.collect_interval):
                params.runtime = None
                STAT['ip'] = {}
                STAT['request'] = {}
                STAT['useragent'] = {}
                STAT['total'] = 0
                STAT['rps_ip'] = {}
                STAT['request_time'] = {}
                STAT['status'] = {}
                params.max_rps = (0, '')
                params.last_rps = 0
                params.collect_interval_last_ts = dt

            cont = False
            for req in params.whitelist_requests:
                if req in request:
                    cont = True
                    break
            if cont:
                continue
            if params.start is not None and params.end is not None:
                if not (params.start <= dt <= params.end):
                    continue
            if params.request is not None and params.request != request:
                continue
            if params.ip is not None and params.ip != ip:
                continue
            if params.agent is not None and params.agent != useragent:
                continue
            if params.status is not None and params.status != status:
                continue
            if params.runtime is None:
                params.runtime = dt
                params.logs = [ip]
            elif params.runtime is not None and (dt - params.runtime).total_seconds() < params.rps_interval:
                params.logs.append(ip)
            elif params.runtime is not None and (dt - params.runtime).total_seconds() >= params.rps_interval:
                params.last_rps = len(params.logs)
                params.last_logs = params.logs
                calc_rps_top(params.logs)
                params.logs = [ip]
                params.runtime = dt

            if params.start_ts is None:
                params.start_ts = dt
            params.close_ts = dt
            if params.last_rps > len(params.max_rps):
                params.max_rps = params.last_logs

            STAT['total'] += 1
            if ip in STAT['ip']:
                STAT['ip'][ip] += 1
            else:
                STAT['ip'][ip] = 1
            if request in STAT['request']:
                STAT['request'][request] += 1
            else:
                STAT['request'][request] = 1
            if useragent in STAT['useragent']:
                STAT['useragent'][useragent] += 1
            else:
                STAT['useragent'][useragent] = 1
            if status in STAT['status']:
                STAT['status'][status] += 1
            else:
                STAT['status'][status] = 1
            if float(request_time) > 0.000:
                key = '{t}:@:{i}:@:{r}'.format(t=dt.timestamp(),
                                               i=ip, r=request)
                STAT['request_time'][key] = float(request_time)

    if params.block or params.block_demo:
        block(params)
    else:
        if params.start_ts is not None and params.close_ts is not None:
            show_stat(params)


def show_stat(params):
    stat = generate_stat(params)
    height, width = params.scr.getmaxyx()
    stdscr = params.stdscr
    stdscr.clear()
    stdscr.scrollok(True)
    def stdscr_refresh(): return stdscr.refresh(0, 0, 0, 0, height-1, width)
    stdscr.addstr(stat)
    stdscr_refresh()
    params.stdscr_contents = stat


def generate_stat(params):
    out = ''
    if params.ip is not None:
        out += 'Filtered by IP: {}\n'.format(params.ip)
    if params.request is not None:
        out += 'Filtered by REQUEST: "{}"\n'.format(params.request)
    if params.agent is not None:
        out += 'Filtered by USER_AGENT: "{}"\n'.format(params.agent)
    run_time = str(params.close_ts - params.start_ts).split('.')[0]
    out += 'Total requests: {t} || '\
        'RPS last: {rs} max: {rm} || '\
        'CPU LA: {la} || '\
        'Run time: {rt} || '\
        'Cur time: {dt}\n\n'.format(t=STAT['total'],
                                    rs=params.last_rps,
                                    rt=run_time,
                                    rm=len(params.max_rps),
                                    dt=str(datetime.datetime.now()).split(
                                        '.')[0],
                                    la=os.getloadavg())

    if params.show_rps:
        out += '-'*40
        out += '\n'
        out += 'TOP {n} IP by RPS\n'.format(n=params.top_count)
        for ip, count in sorted(STAT['rps_ip'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            geo_ip = geo(ip)
            if geo_ip is None:
                geo_ip = ''
            if params.resolve:
                if ip not in DNS:
                    DNS[ip] = socket.getfqdn(ip)
                out += '{v}\t{k}\t({h})\t({g})\n'.format(k=ip, v=count, h=DNS[ip], g=geo_ip)
            else:
                out += '{v}\t{k}\n'.format(k=ip, v=count)

    if params.show_ip:
        out += '-'*40
        out += '\n'
        out += 'TOP {n} by IP (Uniq {c}/{t})\n'.format(n=params.top_count,
                                                        c=len(STAT['ip'].keys()), t=STAT['total'])
        for k, v in sorted(STAT['ip'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            geo_ip = geo(ip)
            if geo_ip is None:
                geo_ip = ''
            if params.resolve:
                if k not in DNS:
                    DNS[k] = socket.getfqdn(k)
                out += '{v}\t{k}\t({h})\t({g})\n'.format(k=k, v=v, h=DNS[k], g=geo_ip)
            else:
                out += '{v}\t{k}\n'.format(k=k, v=v)

    if params.show_request:
        out += '-'*50
        out += '\n'
        out += 'TOP {n} by REQUEST (Uniq {c}/{t})\n'.format(
            n=params.top_count, c=len(STAT['request'].keys()), t=STAT['total'])
        for k, v in sorted(STAT['request'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=k, v=v)

    if params.show_slow_requests:
        out += '-' * 50
        out += '\n'
        out += 'TOP {n} by SLOW REQUESTS (Uniq {c}/{t})\n'.format(
            n=params.top_count, c=len(STAT['request_time'].keys()), t=STAT['total'])
        for k, v in sorted(STAT['request_time'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            dt, ip, req = k.split(':@:')
            out += '{v}\t{t}\t{i}\t{r}\n'.format(
                v=v, t=datetime.datetime.fromtimestamp(float(dt)), i=ip, r=req)

    if params.show_agent:
        out += '-' * 50
        out += '\n'
        out += 'TOP {n} by USER_AGENT (Uniq {c}/{t})\n'.format(
            n=params.top_count, c=len(STAT['useragent'].keys()), t=STAT['total'])
        for k, v in sorted(STAT['useragent'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=k, v=v)

    if params.show_status:
        out += '-' * 50
        out += '\n'
        out += 'TOP {n} by STATUS\n'.format(n=params.top_count)
        for k, v in sorted(STAT['status'].items(), key=lambda kv: kv[1], reverse=True)[:params.top_count]:
            out += '{v}\t{k}\n'.format(k=k, v=v)

    return out


def main(scr=None):
    if not params.block and not params.block_demo:
        scr.keypad(True)
        curses.noecho()
        height, width = scr.getmaxyx()
        scr.refresh()
        scr.clear()
        stdscr = curses.newpad(height+100, width)
        params.stdscr = stdscr
        params.scr = scr

    if params.path is None:
        error('Bad value for argument --path : "{}"'.format(params.path))
        quit(0)
    for f in get_files(params.path):
        params.log = f
        parse(params)


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
    parser.add_argument(
        '--show', nargs='+', help='Which type of TOP to show: "rps", "ip", "req", "agent", "status", "slow"')
    parser.add_argument('--count', '-с', dest='top_count',
                        type=int, help="Number of TOP records")
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

    debug('Starting')
    try:
        if not params.block and not params.block_demo:
            curses.wrapper(main)
        else:
            main()
    except KeyboardInterrupt:
        pass
    except Exception as er:
        debug(traceback.format_exc())
        error(er)
    finally:
        for l in params.stdscr_contents.splitlines():
            info(str(l).strip().lstrip('b').strip("'").strip())
    debug('Shutting down')
