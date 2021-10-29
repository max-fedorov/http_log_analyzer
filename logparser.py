import logging
import re
import time
import datetime
import geoip2.database
import socket
import calendar

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

month_cal = dict((v, k) for v, k in zip(calendar.month_abbr[1:], range(1, 13)))


class RequestParams:
    def __init__(self) -> None:
        self.id = time.time()
        self.ip = None
        self.user = None
        self.request_url = None
        self.size = None
        self.referrer = None
        self.user_agent = None
        self.status_code = None
        self.upstream_response_time = None
        self.upstream = None
        self.request_time = None
        self.host = None
        self.reverse_dns = None
        self.geo = None
        self.datetime = None
        self.log_line = None


class Ip:
    def __init__(self) -> None:
        self.name = None
        self.dns = None
        self.geo = None
        self.requests = []


class Geo:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class RequestUrl:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class UserAgent:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class SlowRequest:
    def __init__(self) -> None:
        self.name = None
        self.time = None


class StatusCode:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class Rps:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class Host:
    def __init__(self) -> None:
        self.name = None
        self.requests = []


class Log:
    def __init__(self, params) -> None:
        self._logger = logging.getLogger(__class__.__name__)
        self.all_requests = {}
        self.requests_per_interval = {}
        self.ip = {}
        self.request_url = {}
        self.user_agent = {}
        self.geo = {}
        self.slow_request = {}
        self.status_code = {}
        self.rps = {}
        self.host = {}
        self.global_params = params
        self.total = 0
        self.db_dns = {}
        self.db_geo = {}

    def process_log_line(self, line: str) -> RequestParams:
        request = RequestParams()
        request.log_line = line
        sep = r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])'
        try:
            args = [el.strip('[]"') for el in re.split(sep, line)]
            request.ip = args[0]
            request.user = args[2]
            dt = self.string_to_datetime(args[3])
            request.datetime = dt
            request.request_url = args[4]
            request.status_code = args[5]
            request.size = args[6]
            request.referrer = args[7]
            request.user_agent = args[8]
            request.upstream = args[9]
            request.upstream_response_time = args[10]
            request.request_time = args[11]
            request.host = args[12]
        except Exception:
            pass
            #self._logger.debug(f'ERROR: parse line "{line}"')
        return request

    def parse(self, data: str):
        new_requests = []
        for l in data.splitlines():
            request = self.process_log_line(l)
            if request.ip is None: continue
            if self.global_params.processed_first_request_datetime is None:
                self.global_params.processed_first_request_datetime = request.datetime
            self.global_params.processed_last_request_datetime = request.datetime
            self.global_params.processed_requests_total += 1
            if request.ip not in self.db_dns:
                if self.global_params.resolve:
                    self.db_dns[request.ip] = socket.getfqdn(request.ip).lower()
                else:
                    self.db_dns[request.ip] = '--'
            request.reverse_dns = self.db_dns[request.ip]
            if request.ip not in self.db_geo:
                self.db_geo[request.ip] = self.get_geo(request.ip)
            request.geo = self.db_geo[request.ip]
            self.process(request)
            new_requests.append(request)
        return new_requests

    def process(self, request: RequestParams):
        if self.global_params.collect_interval_last_ts is None:
            self.global_params.collect_interval_last_ts = request.datetime
        if request.datetime - self.global_params.collect_interval_last_ts >= datetime.timedelta(
                minutes=self.global_params.collect_interval):
            self.global_params.runtime = None
            self.ip = {}
            self.request_url = {}
            self.user_agent = {}
            self.geo = {}
            self.host = {}
            self.slow_request = {}
            self.status_code = {}
            self.rps = {}
            self.total = 0
            self.global_params.max_rps = (0, '')
            self.global_params.last_rps = 0
            self.global_params.collect_interval_last_ts = request.datetime

        for req in self.global_params.whitelist_requests:
            if req in request.request_url:
                return
        if self.global_params.start is not None and self.global_params.end is not None:
            if not (self.global_params.start <= request.datetime <= self.global_params.end):
                return
        if self.global_params.request is not None and self.global_params.request != request.request_url:
            return
        if self.global_params.ip is not None and self.global_params.ip != request.ip:
            return
        if self.global_params.agent is not None and self.global_params.agent != request.user_agent:
            return
        if self.global_params.status is not None and self.global_params.status != request.status_code:
            return
        if self.global_params.host is not None and self.global_params.host != request.host:
            return
        if self.global_params.runtime is None:
            self.global_params.runtime = request.datetime
            self.requests_per_interval = [request.id]
        elif self.global_params.runtime is not None and (
                request.datetime - self.global_params.runtime).total_seconds() < self.global_params.rps_interval:
            self.requests_per_interval.append(request.id)
        elif self.global_params.runtime is not None and (
                request.datetime - self.global_params.runtime).total_seconds() >= self.global_params.rps_interval:
            self.global_params.last_rps = len(self.requests_per_interval)
            self.global_params.last_logs = self.requests_per_interval
            self.calc_rps_top(self.requests_per_interval)
            self.requests_per_interval = [request.id]
            self.global_params.runtime = request.datetime

        if self.global_params.start_ts is None:
            self.global_params.start_ts = request.datetime
        self.global_params.close_ts = request.datetime
        if self.global_params.last_rps > len(self.global_params.max_rps):
            self.global_params.max_rps = self.global_params.last_logs

        self.total += 1
        self.all_requests[request.id] = request
        try:
            if request.ip in self.ip:
                self.ip[request.ip].requests.append(request.id)
            else:
                self.ip[request.ip] = Ip()
                self.ip[request.ip].name = request.ip
                self.ip[request.ip].requests.append(request.id)
                self.ip[request.ip].dns = request.reverse_dns
                self.ip[request.ip].geo = request.geo

            if request.request_url in self.request_url:
                self.request_url[request.request_url].requests.append(request.id)
            else:
                self.request_url[request.request_url] = RequestUrl()
                self.request_url[request.request_url].name = request.request_url
                self.request_url[request.request_url].requests.append(request.id)

            if request.user_agent in self.user_agent:
                self.user_agent[request.user_agent].requests.append(request.id)
            else:
                self.user_agent[request.user_agent] = UserAgent()
                self.user_agent[request.user_agent].name = request.user_agent
                self.user_agent[request.user_agent].requests.append(request.id)

            if request.status_code in self.status_code:
                self.status_code[request.status_code].requests.append(request.id)
            else:
                self.status_code[request.status_code] = StatusCode()
                self.status_code[request.status_code].name = request.status_code
                self.status_code[request.status_code].requests.append(request.id)

            if request.geo in self.geo:
                self.geo[request.geo].requests.append(request.id)
            else:
                self.geo[request.geo] = Geo()
                self.geo[request.geo].name = request.geo
                self.geo[request.geo].requests.append(request.id)

            if request.host in self.host:
                self.host[request.host].requests.append(request.id)
            else:
                self.host[request.host] = Host()
                self.host[request.host].name = request.host
                self.host[request.host].requests.append(request.id)

            if request.request_time is not None and float(request.request_time) > 0.000:
                # key = '{t}:@:{i}:@:{r}'.format(t=request.datetime.timestamp(),
                #                            i=request.ip, r=request.request_url)
                self.slow_request[request.id] = SlowRequest()
                self.slow_request[request.id].time = float(request.request_time)
                self.slow_request[request.id].name = request.request_url
        except ValueError as er:
            self._logger.debug(f'{er}')
            self._logger.debug(request.log_line)

    @staticmethod
    def get_geo(ip: str) -> str:
        out = '---'
        try:
            q = geoip2.database.Reader('geoip.mmdb')
            geo = q.city(ip)
            out = geo.country.name
        except Exception:
            pass
        return out

    def calc_rps_top(self, logs: list):
        tmp_rps = {}
        for k in logs:
            request = self.all_requests[k]
            if request.ip in tmp_rps:
                tmp_rps[request.ip].requests.append(request.id)
            else:
                tmp_rps[request.ip] = Rps()
                tmp_rps[request.ip].name = request.ip
                tmp_rps[request.ip].requests.append(request.id)

        for k in tmp_rps.keys():
            if k in self.rps:
                if len(tmp_rps[k].requests) > len(self.rps[k].requests):
                    self.rps[k].requests = tmp_rps[k].requests
            else:
                self.rps[k] = tmp_rps[k]

    @staticmethod
    def string_to_datetime(data):
        '''input format example: 07/Oct/2021:13:54:16 +0300'''
        date, hour, minute, second = data.split()[0].split(':')
        day, month, year = date.split('/')
        month = month_cal[month]
        # disabled for python < 3.7
        # return datetime.datetime.fromisoformat(f'{year}-{month}-{day} {hour}:{minute}:{second}')
        return datetime.datetime(year=int(year), month=int(month), day=int(day), hour=int(hour), minute=int(minute),
                                 second=int(second))
