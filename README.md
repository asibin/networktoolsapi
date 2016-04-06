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
 
Just install requirements from requirements file:

```bash
pip install -r requirements.txt
```

and run `runserver.py` for local development (port 5000).

In order to have geoip available you need to download Maxmind's databases and put them into networktoolsapi/static/data folder as `GeoIPCity.dat` and `GeoIPISP.dat`:


## Documentation

Full documentation link TBA.

In the meanwhile you can build your local documentation by going to `docs` folder and running:

```bash
build html
```

you will find your documentation in `_build/html` folder, just open `index.html`.