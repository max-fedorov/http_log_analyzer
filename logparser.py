import logging
import re
import time
import datetime
import geoip2.database
import socket


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


class RequestParams:
    def __init__(self) -> None:
        self.id = time.time()
        self.ip = None
        self.request_url = None
        self.bytessent = None
        self.referrer = None
        self.user_agent = None
        self.status_code = None
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
        self.global_params = params
        self.total = 0
        self.db_dns = {}
        self.db_geo = {}

    def parse(self, data: str):
        new_requests = []
        for l in data.splitlines():
            data = re.search(log_format, l)
            if data:
                request = RequestParams()
                datadict = data.groupdict()
                request.ip = datadict['ip']
                request.request_url = datadict['request']
                request.bytessent = datadict['bytessent']
                request.referrer = datadict['referrer']
                request.user_agent = datadict['useragent']
                request.status_code = datadict['status']
                request.host = datadict['host']
                request.request_time = datadict['request_time']
                request.log_line = l
                datetimestring = datadict['datetime']
                dt = datetime.datetime.strptime(
                    datetimestring.split()[0], '%d/%b/%Y:%H:%M:%S')
                request.datetime = dt
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
            else:
                self._logger.debug('Fail to parse line: "{}"'.format(l))
        return new_requests

    def process(self, request: RequestParams):
        if self.global_params.collect_interval_last_ts is None:
            self.global_params.collect_interval_last_ts = request.datetime
        if request.datetime - self.global_params.collect_interval_last_ts >= datetime.timedelta(minutes=self.global_params.collect_interval):
            self.global_params.runtime = None
            self.ip = {}
            self.request_url = {}
            self.user_agent = {}
            self.geo = {}
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
        if self.global_params.runtime is None:
            self.global_params.runtime = request.datetime
            self.requests_per_interval = [request.id]
        elif self.global_params.runtime is not None and (request.datetime - self.global_params.runtime).total_seconds() < self.global_params.rps_interval:
            self.requests_per_interval.append(request.id)
        elif self.global_params.runtime is not None and (request.datetime - self.global_params.runtime).total_seconds() >= self.global_params.rps_interval:
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

            if float(request.request_time) > 0.000:
                # key = '{t}:@:{i}:@:{r}'.format(t=request.datetime.timestamp(),
                #                            i=request.ip, r=request.request_url)
                self.slow_request[request.id] = SlowRequest()
                self.slow_request[request.id].time = request.request_time
                self.slow_request[request.id].name = request.request_url
        except ValueError as er:
            self._logger.error(er)
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
