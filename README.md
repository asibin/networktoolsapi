[![Build Status](https://travis-ci.org/asibin/networktoolsapi.svg?branch=master)](https://travis-ci.org/asibin/networktoolsapi)


# NETWORK TOOLS API

Flask based API for getting JSON information on:
* dns: shows all DNS records - hosts, MX, NS, SOA, TXT. Specify DNS servers with `?q=8.8.8.8,8.8.4.4`, defaults to google DNS servers
* whois: shows whois data for requested domain
* ipwhois: shows whois data for IP addresses
* geoip: shows geoip data for resolved IPs
* host: shows nmap scan of host or ip/netmask addresses, list of hosts UP, list of hosts DOWN, and separate list of hostnames and statuses
* nmap: like hosts but shows complete port scan
* ipcalc: calculates IP subnets based on netmask, also returns basic IP data, can print all IPs in range with `?iplist`

**Disclaimer:** standard nmap limitations apply here! This is a service on public IP it **can not** access local networks behind firewalls.

In order to have geoip available you need to download Maxmind's databases and put them into `networktoolsapi/static/data` folder as `GeoIPCity.dat` and `GeoIPISP.dat`.
Please note that GeoIP ISP database is not free and is part of the MaxMind's paid tier, however if you don't want to use paid tier you can use `GeoLite ASN` 
database to get at least ASN number of the ISP. There are a few different ways to get ISP name from ASN, if you want to add this functionality submit a pull request.
Change filename in `settings.py` under `ISP_MMDB_LOCATION` to use different database. This project defaults to free databases but is easily used with paid ones.

Just install requirements from requirements file:

```bash
pip install -r requirements.txt
```

and run `runserver.py` for local development (port 5000).

## Documentation

Full documentation link TBA.

In the meanwhile you can build your local documentation by going to `docs` folder and running:

```bash
build html
```

you will find your documentation in `_build/html` folder, just open `index.html`.