import geoip2.database

def geo(ip):
    out = None
    try:
        q =geoip2.database.Reader('geoip.mmdb')
        geo = q.city(ip)
        #out = '{}/{}'.format(geo.country.name,geo.city.name)
        out = geo.country.name
    except Exception:
        pass
    return out