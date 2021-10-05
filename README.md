# http_log_analyzer

###### 1. Install

Requirements: yum install gcc python36-devel

```
cd /opt
git clone git@github.com:skam/http_log_analyzer.git
cd http_log_analizer/
python3 -m venv env
source env/bin/activate
pip  install -r requirements.txt
deactivate
```

###### 2. Configure
```
cp .http_log_analyzer.yml.sample .http_log_analyzer.yml
vim .http_log_analyzer.yml
```
1. define path to log file
2. adjust block_threshold_rps and block_threshold_ip
3. set whitelist_ip

###### 3. Test run
```/opt/http_log_analizer/http_log_analizer.py```

###### 4. Add systemd service
```
ln -s /opt/http_log_analizer/http_log_analyzer.service /etc/systemd/system/http_log_analyzer.service
systemctl daemon-reload
systemctl enable http_log_analyzer
systemctl start http_log_analyzer
systemctl status http_log_analyzer
```

###### 5. Add cron task to unblock IPs when time is gone
```
cat > /etc/cron.d/http_log_analizer_unblock
* * * * * root /opt/http_log_analizer/iptctl.py > /dev/null 2>&1
```