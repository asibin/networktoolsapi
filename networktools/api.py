"""
Main API functionality
"""

import sys
import socket
import logging
import nmap
import pygeoip
import math

from pythonwhois import get_whois
from pythonwhois.shared import WhoisException
from dns import exception, resolver
from flask import request, jsonify, render_template, abort
from ipwhois import IPWhois, ASNLookupError, IPDefinedError, ASNRegistryError, HostLookupError, BlacklistError
from netaddr import IPNetwork, AddrFormatError, AddrConversionError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from networktools import app
from networktools import errors

logging.basicConfig(level=app.config['LOG_LEVEL'], format="[%(asctime)s][%(levelname)s] - %(message)s")
logger = logging.getLogger(__name__)
logger.info(r"""
  _   _      _                      _    _____           _          _    ____ ___
 | \ | | ___| |___      _____  _ __| | _|_   _|__   ___ | |___     / \  |  _ \_ _|
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | |/ _ \ / _ \| / __|   / _ \ | |_) | |
 | |\  |  __/ |_ \ V  V / (_) | |  |   <  | | (_) | (_) | \__ \  / ___ \|  __/| |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |_|\___/ \___/|_|___/ /_/   \_\_|  |___|

""")

ALLOWED_IPS = app.config['ALLOWED_IPS']

try:
    CITY_MMDB = pygeoip.GeoIP(app.config['CITY_MMDB_LOCATION'])
    ISP_MMDB = pygeoip.GeoIP(app.config['ISP_MMDB_LOCATION'])
except IOError as e:
    logger.critical("Cannot open GEOIP database: %s", str(e))

limiter = Limiter(app,
                  key_func=get_remote_address,
                  global_limits=app.config['LIMITER_GLOBAL_LIMITS'])


@app.before_request
def acl():
    """
    Decorator that checks if visitor's IP address is in the list of allowed IP addresses and aborts if it isn't.
    Leave empty list in case you don't want to use IP restrictions
    """
    if request.remote_addr not in ALLOWED_IPS and len(ALLOWED_IPS) > 0:
        logger.debug("IP not in list of allowed IPs: %s", request.remote_addr)
        abort(403)
    elif len(ALLOWED_IPS) == 0:
        logger.debug("No IPs defined in whitelist")
        logger.debug("Allowing access to: %s", request.remote_addr)
        return


def hostname_resolves(hostname):
    resolved_ips = []

    logger.debug("Hostname to resolve: %s", str(hostname))

    try:
        ips = socket.getaddrinfo(hostname, None)
        for ip in ips:
            if ip[4][0] not in resolved_ips:
                net = IPNetwork(ip[4][0])
                if net.is_private() or net.is_link_local():
                    logger.warning("Tried to resolve local IP: %s, ignoring!", ip[4][0])
                    continue
                else:
                    resolved_ips.append(ip[4][0])

        if len(resolved_ips) > 0:
            logger.debug("Resolved IPs: %s", ', '.join(resolved_ips))
            return resolved_ips
        else:
            logger.warning("No IPs resolved from query: %s", hostname)
            abort(400)

    except socket.gaierror:
        logger.debug("Failed to resolve IP address from: %s", hostname)
        abort(400)


def get_ipwhois(ip):
    try:
        ipwhois_query = IPWhois(ip)
        logger.debug(ipwhois_query)
    except ASNLookupError as e:
        return str(e)
    except IPDefinedError as e:
        return str(e)
    except ASNRegistryError as e:
        return str(e)
    except HostLookupError as e:
        return str(e)
    except BlacklistError as e:
        return str(e)

    ipwhois_result = ipwhois_query.lookup()
    return ipwhois_result


def error_response(msg, rc):
    """
    Returns properly formatted error api response
    :param msg: Human readable error message
    :param rc: HTTP return code
    :return: JSON formatted error response
    """
    return jsonify({'status': 'error',
                    'msg': str(msg)}), rc


def geoip_distance(lat1, long1, lat2, long2, metric=True):
    """
    Calculates distance between two points on spherical earth.

    Source: http://www.johndcook.com/blog/python_longitude_latitude/

    :param lat1: Latitude of the first point
    :param long1: Longitude of the second point
    :param lat2: Latitude of the second point
    :param long2: Longitude of the second point
    :param metric: if true returns km, else returns miles
    :return: Distance in km
    """

    degrees_to_radians = math.pi / 180.0

    phi1 = (90.0 - lat1) * degrees_to_radians
    phi2 = (90.0 - lat2) * degrees_to_radians

    theta1 = long1 * degrees_to_radians
    theta2 = long2 * degrees_to_radians

    cos = (math.sin(phi1) * math.sin(phi2) * math.cos(theta1 - theta2) + math.cos(phi1) * math.cos(phi2))
    arc = math.acos(cos)

    if metric:
        return arc * 6371, "km"
    else:
        return arc * 3959, "mi"


@app.route('/')
def return_whatismyip():
    """
    Simple page with user's IP address information
    :return: What Is My IP page
    """
    error = {}
    visitor_ip = request.remote_addr

    geoip = CITY_MMDB.record_by_addr(visitor_ip)
    isp = ISP_MMDB.org_by_addr(visitor_ip)

    ipwhois_info = get_ipwhois(visitor_ip)

    if isinstance(ipwhois_info, basestring):  # If we don't get the hash results we got an exception
        error = ipwhois_info
    return render_template('whatismyip.html',
                           ip=visitor_ip,
                           geoip=geoip,
                           isp=isp,
                           whois_info=ipwhois_info,
                           error=error)


@app.route('/plain')
def return_ip():
    """
    Curl / copy friendly external IP information. Could be wrong if behind proxy.
    :return: Public IP address of requestor
    """
    visitor_ip = request.remote_addr
    return render_template('ip.html', ip=visitor_ip)


# API FUNCTIONS

@app.route('/api/geoip/<string:query>', methods=['GET'])
def return_geoip(query):
    """
    Geoip query, accepts IP or FQDN. FQDN is resolved to ip and then queried for geoip data.
    Google maps url in response for quick access. Distance available in metric and imperial measurements.
    Defaults to metric. Add ``?imperial`` to get distance in miles.

    :param query: IP or FQDN

    **Example:**

        **GET:** ``/api/nmap/8.8.8.8``

        ::

            {
                "geoip": [
                {
                    "area_code": 650,
                    "city": "Mountain View",
                    "continent": "NA",
                    "country_code": "US",
                    "country_code3": "USA",
                    "country_name": "United States",
                    "distance": 830
                    "distance_unit": "km"
                    "dma_code": 807,
                    "google_maps_url": "http://maps.google.com/maps?q=loc:37.386,-122.0838",
                    "ip": "8.8.8.8",
                    "isp": "Google",
                    "latitude": 37.385999999999996,
                    "longitude": -122.0838,
                    "metro_code": "San Francisco, CA",
                    "postal_code": "94040",
                    "region_code": "CA",
                    "time_zone": "America/Los_Angeles"
                }],
                "resolved_ips": [
                    "8.8.8.8"
                ],
                "status": "ok"
            }
    """
    hosts = []

    resolved_ip = hostname_resolves(query)

    visitor_ip = request.remote_addr
    visitor_geoip = CITY_MMDB.record_by_addr(visitor_ip)

    args = request.args.get('imperial')

    if args is not None:
        metric = False
    else:
        metric = True

    for ip in resolved_ip:
        logger.debug(ip)
        geoip = CITY_MMDB.record_by_addr(ip)
        geoip['ip'] = ip

        isp = ISP_MMDB.org_by_addr(ip)
        geoip['isp'] = isp

        geoip['google_maps_url'] = "http://maps.google.com/maps?q=loc:{},{}".format(geoip['latitude'],
                                                                                    geoip['longitude'])

        if visitor_geoip is not None:
            distance, unit = geoip_distance(visitor_geoip['latitude'], visitor_geoip['longitude'],
                                            geoip['latitude'], geoip['longitude'], metric=metric)
            geoip['distance'] = distance
            geoip['distance_unit'] = unit
        else:
            geoip['distance'] = None
            geoip['distance_unit'] = None

        hosts.append(geoip)

    logger.debug("GeoIP hosts: {}".format(hosts))

    return jsonify({'status': "ok",
                    'resolved_ips': resolved_ip,
                    'geoip': hosts})


@app.route('/api/ipwhois/<string:ipquery>', methods=['GET'])
def return_ipwhois(ipquery):
    """
    IP whois query, accepts IP or FQDN. FQDN is resolved to ip and then queried for ipwhois data.
    Returns IP address and network's registered user.

    :param ipquery: IP or FQDN

    **Example:**

        **GET:** ``/api/ipwhois/84.20.255.11``

        ::

           {
                ipwhois: [
                {
                    asn: "15169",
                    asn_cidr: "8.8.8.0/24",
                    asn_country_code: "US",
                    asn_date: "",
                    asn_registry: "arin",
                    nets: [
                    {
                        address: "1025 Eldorado Blvd.",
                        cidr: "8.0.0.0/8",
                        city: "Broomfield",
                        country: "US",
                        created: "1992-12-01",
                        description: "Level 3 Communications, Inc.",
                        emails: "noc.coreip@level3.com abuse@level3.com ipaddressing@level3.com",
                        handle: "NET-8-0-0-0-1",
                        name: "LVLT-ORG-8-8",
                        postal_code: "80021",
                        range: "8.0.0.0 - 8.255.255.255",
                        state: "CO",
                        updated: "2012-02-24"
                        },
                        {
                            address: "1600 Amphitheatre Parkway",
                            cidr: "8.8.8.0/24",
                            city: "Mountain View",
                            country: "US",
                            created: "2014-03-14",
                            description: "Google Inc.",
                            emails: "network-abuse@google.com arin-contact@google.com",
                            handle: "NET-8-8-8-0-1",
                            name: "LVLT-GOGL-8-8-8",
                            postal_code: "94043",
                            range: null,
                            state: "CA",
                            updated: "2014-03-14"
                        }
                        ],
                        query: "8.8.8.8",
                        raw: null,
                        raw_referral: null,
                        referral: null
                    }
                    ],
                    status: "ok"
                }
            }

    """

    hosts = []
    resolved_ip = hostname_resolves(ipquery)

    for ip in resolved_ip:
        hosts.append(get_ipwhois(ip))

    return jsonify({'ipwhois': hosts,
                    'status': "ok"})


@app.route('/api/whois/<string:query>', methods=['GET'])
def return_whois(query):
    """
    Whois query, accepts IP or FQDN. FQDN is resolved to ip and then queried for ipwhois data.

    :param query: IP or FQDN

    **Example:**

        $ GET ``/api/whois/1-up.xyz``

        ::

            {
              status: "ok",
              whois: {
                contacts: {
                  admin: {
                    city: "Panama",
                    country: "PA",
                    email: "5cc1435e8bae40bf8275d28a2150b6bf.protect@whoisguard.com",
                    fax: "+51.17057182",
                    handle: "C44073503-CNIC",
                    name: "WhoisGuard Protected",
                    organization: "WhoisGuard, Inc.",
                    phone: "+507.8365503",
                    postalcode: "00000",
                    state: "Panama",
                    street: "P.O. Box 0823-03411"
                  },
                  billing: {
                    city: "Panama",
                    country: "PA",
                    email: "5cc1435e8bae40bf8275d28a2150b6bf.protect@whoisguard.com",
                    fax: "+51.17057182",
                    handle: "C44073504-CNIC",
                    name: "WhoisGuard Protected",
                    organization: "WhoisGuard, Inc.",
                    phone: "+507.8365503",
                    postalcode: "00000",
                    state: "Panama",
                    street: "P.O. Box 0823-03411"
                  },
                  registrant: {
                    city: "Panama",
                    country: "PA",
                    email: "5cc1435e8bae40bf8275d28a2150b6bf.protect@whoisguard.com",
                    fax: "+51.17057182",
                    handle: "C44073500-CNIC",
                    name: "WhoisGuard Protected",
                    organization: "WhoisGuard, Inc.",
                    phone: "+507.8365503",
                    postalcode: "00000",
                    state: "Panama",
                    street: "P.O. Box 0823-03411"
                  },
                  tech: {
                    city: "Panama",
                    country: "PA",
                    email: "5cc1435e8bae40bf8275d28a2150b6bf.protect@whoisguard.com",
                    fax: "+51.17057182",
                    handle: "C44073507-CNIC",
                    name: "WhoisGuard Protected",
                    organization: "WhoisGuard, Inc.",
                    phone: "+507.8365503",
                    postalcode: "00000",
                    state: "Panama",
                    street: "P.O. Box 0823-03411"
                  }
                },
                creation_date: [
                  "Thu, 10 Mar 2016 12:13:09 GMT"
                ],
                emails: [
                  "abuse@namecheap.com"
                ],
                expiration_date: [
                  "Fri, 10 Mar 2017 23:59:59 GMT"
                ],
                id: [
                  "D18499062-CNIC"
                ],
                nameservers: [
                  "dns1.registrar-servers.com",
                  "dns2.registrar-servers.com",
                  "dns3.registrar-servers.com",
                  "dns4.registrar-servers.com",
                  "dns5.registrar-servers.com"
                ],
                raw: [
                  "Domain name: 1-up.xyz Registry Domain ID: D18499062-CNIC Registrar WHOIS Server: whois.namecheap.com
                  ...
                  For more information, please see https://registrar-console.centralnic.com/pub/whois_guidance. "
                ],
                registrar: [
                  "NAMECHEAP INC"
                ],
                status: [
                  "clientTransferProhibited",
                  "serverTransferProhibited",
                  "addPeriod"
                ],
                updated_date: [
                  "Thu, 10 Mar 2016 12:13:12 GMT"
                ],
                whois_server: [
                  "whois.namecheap.com"
                ]
              }
            }
    """

    try:
        result = get_whois(query)
    except WhoisException as e:
        return error_response(e, 400)

    if result:
        return jsonify({'whois': result,
                        'status': "ok"})
    else:
        abort(400)


@app.route('/api/dns/<string:query>', methods=['GET'])
def return_dns(query):
    """
    DNS query, accepts IP or FQDN. FQDN is resolved to ip and then queried for dns data.
    You can specify multiple alternative DNS server to query by specifying ``?q=<dns_ip1>,<dns_ip2>``.
    If you do not specify DNS servers with ``?q=`` default server are ``8.8.8.8,8.8.4.4``

    :returns Host records (A), MX records, NS records, SOA, TXT records

    :param query: IP or FQDN

    **Example:**

        $ GET ``/api/dns/1-up.xyz``

        ::

            {
              "hosts": {
                "records": [
                  {
                    "address": "162.255.119.250",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "A"
                  }
                ]
              },
              "mx": {
                "records": [
                  {
                    "address": "eforward1.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "priority": "10",
                    "type": "MX"
                  },
                  {
                    "address": "eforward4.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "priority": "15",
                    "type": "MX"
                  },
                  {
                    "address": "eforward5.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "priority": "20",
                    "type": "MX"
                  },
                  {
                    "address": "eforward2.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "priority": "10",
                    "type": "MX"
                  },
                  {
                    "address": "eforward3.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "priority": "10",
                    "type": "MX"
                  }
                ]
              },
              "ns": {
                "records": [
                  {
                    "address": "dns2.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "NS"
                  },
                  {
                    "address": "dns1.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "NS"
                  },
                  {
                    "address": "dns3.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "NS"
                  },
                  {
                    "address": "dns5.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "NS"
                  },
                  {
                    "address": "dns4.registrar-servers.com.",
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "type": "NS"
                  }
                ]
              },
              "soa": {
                "records": [
                  {
                    "class": "IN",
                    "dns_contact": "hostmaster.registrar-servers.com.",
                    "expire": "604800",
                    "expires_in": "3600",
                    "minimum": "3601",
                    "name": "1-up.xyz.",
                    "primary_ns": "dns1.registrar-servers.com.",
                    "refresh": "43200",
                    "retry": "3600",
                    "serial": "2016031003",
                    "type": "SOA"
                  }
                ]
              },
              "status": "ok",
              "txt": {
                "records": [
                  {
                    "class": "IN",
                    "expires_in": "1799",
                    "name": "1-up.xyz.",
                    "string": "\"v=spf1 include:spf.efwd.registrar-servers.com ~all\"",
                    "type": "TXT"
                  }
                ]
              }
            }
    """

    dns_dict = {}
    dns_servers = []

    querier = resolver.Resolver(configure=False)  # Don't use /etc/resolv.conf

    args = request.args.get('q')

    if args is not None:
        for arg in args.split(','):
            dns_servers.append(arg)
        querier.nameservers = dns_servers
        logger.debug("Nameservers: " + ", ".join(querier.nameservers))
    else:
        querier.nameservers = app.config.get('DEFAULT_NAMESERVERS')

    try:
        dns_records = querier.query(query, raise_on_no_answer=False)
        mail_records = querier.query(query, 'MX', raise_on_no_answer=False)
        ns_records = querier.query(query, 'NS', raise_on_no_answer=False)
        soa_records = querier.query(query, 'SOA', raise_on_no_answer=False)
        txt_records = querier.query(query, 'TXT', raise_on_no_answer=False)
    except resolver.NXDOMAIN:
        return error_response("Non-existent Domain Name (NXDOMAIN)", 400)
    except resolver.Timeout:
        return error_response("Request timed out", 200)
    except resolver.NoNameservers:
        return error_response("No name servers", 200)
    except resolver.NoAnswer:
        return error_response("No answer", 200)
    except resolver.NoRootSOA:
        return error_response("No root SOA", 200)
    except resolver.NoMetaqueries:
        return error_response("No meta queries", 200)
    except exception.DNSException:
        return error_response("Couldn't resolve domain name", 400)

    if dns_records.rrset is None:
        return error_response("No A or AAAA records for this domain name", 200)

    dns_dict['records'] = []
    split_dns_records = dns_records.rrset.to_text().split('\n')

    for line in split_dns_records:
        line = line.split(" ")
        dns_dict['records'].append({'name': line[0],
                                    'expires_in': line[1],
                                    'class': line[2],
                                    'type': line[3],
                                    'address': line[4]})

    mx_dict = dict()
    mx_dict['records'] = []
    if mail_records.rrset is not None:
        split_mail_records = mail_records.rrset.to_text().split('\n')
        for line in split_mail_records:
            line = line.split(" ")
            mx_dict['records'].append({'name': line[0],
                                       'expires_in': line[1],
                                       'class': line[2],
                                       'type': line[3],
                                       'priority': line[4],
                                       'address': line[5]})

    soa_dict = dict()
    soa_dict['records'] = []
    if soa_records.rrset is not None:
        split_soa_records = soa_records.rrset.to_text().split('\n')
        for line in split_soa_records:
            line = line.split(" ")
            soa_dict['records'].append({'name': line[0],
                                        'expires_in': line[1],
                                        'class': line[2],
                                        'type': line[3],
                                        'primary_ns': line[4],
                                        'dns_contact': line[5],
                                        'serial': line[6],
                                        'refresh': line[7],
                                        'retry': line[8],
                                        'expire': line[9],
                                        'minimum': line[10]})

    ns_dict = dict()
    ns_dict['records'] = []
    if ns_records.rrset is not None:
        split_ns_records = ns_records.rrset.to_text().split('\n')
        for line in split_ns_records:
            line = line.split(" ")
            ns_dict['records'].append({'name': line[0],
                                       'expires_in': line[1],
                                       'class': line[2],
                                       'type': line[3],
                                       'address': line[4]})

    txt_dict = dict()
    txt_dict['records'] = []
    if txt_records.rrset is not None:
        split_txt_records = txt_records.rrset.to_text().split('\n')
        for line in split_txt_records:
            line = line.split(" ", 4)
            txt_dict['records'].append({'name': line[0],
                                        'expires_in': line[1],
                                        'class': line[2],
                                        'type': line[3],
                                        'string': line[4]})

    return jsonify({'status': "ok",
                    'hosts': dns_dict,
                    'mx': mx_dict,
                    'soa': soa_dict,
                    'ns': ns_dict,
                    'txt': txt_dict})


@app.route('/api/host/<string:query>')
@app.route('/api/host/<string:query>/<string:netmask>')
def get_nmap_network(query, netmask=""):
    """
    Shows IP's that are pingable and those that are not. Accepts netmask to define the whole range for scan.
    Uses NMAP's **-sP** to probe hosts. Probing is done from Hosting machine and therefore not suitable for
    scanning local network ranges. Useful when checking how many IP's you have left in a particular netmask.

    :param query: IP address or hostname
    :param netmask: (Optional) If you want to scan the whole range of hosts

    **Example:**

        $ GET ``/api/host/199.16.156.102/29``

        ::


            {
              "down": [
                "199.16.156.100",
                "199.16.156.101",
                "199.16.156.96",
                "199.16.156.97",
                "199.16.156.98",
                "199.16.156.99"
              ],
              "hosts": [
                {
                  "host": "199.16.156.100",
                  "hostname": [],
                  "status": "down"
                },
                {
                  "host": "199.16.156.101",
                  "hostname": [],
                  "status": "down"
                },
                {
                  "host": "199.16.156.102",
                  "hostname": [],
                  "status": "up"
                },
                {
                  "host": "199.16.156.103",
                  "hostname": [],
                  "status": "up"
                },
                {
                  "host": "199.16.156.96",
                  "hostname": [],
                  "status": "down"
                },
                {
                  "host": "199.16.156.97",
                  "hostname": [],
                  "status": "down"
                },
                {
                  "host": "199.16.156.98",
                  "hostname": [],
                  "status": "down"
                },
                {
                  "host": "199.16.156.99",
                  "hostname": [],
                  "status": "down"
                }
              ],
              "status": "ok",
              "up": [
                "199.16.156.102",
                "199.16.156.103"
              ]
            }

    """
    try:
        nm = nmap.PortScanner()
        hosts = dict()

        hosts['hosts'] = []
        hosts['up'] = []
        hosts['down'] = []

        if netmask == "":
            to_query = query
        else:
            to_query = query + "/" + netmask

        logger.debug(to_query)

        try:
            net = IPNetwork(to_query)
        except AddrFormatError:
            abort(400)

        if net.is_link_local() or net.is_private():  # Won't scan server's local network
            abort(400)

        nm.scan(hosts=to_query, arguments='-sn -v')

        hosts_list = [(x, nm[x]) for x in nm.all_hosts()]

        logger.debug(hosts_list)

        for host, status in hosts_list:
            hosts['hosts'].append({'host': host,
                                   'status': status['status']['state'],
                                   'hostname': status['hostnames']})

            if status['status']['state'] == 'up':
                hosts['up'].append(host)

            if status['status']['state'] == 'down':
                hosts['down'].append(host)

        return jsonify({'status': "ok",
                        'hosts': hosts['hosts'],
                        'up': hosts['up'],
                        'down': hosts['down']})

    except nmap.PortScannerError:
        return error_response("Nmap error, can't scan", 500)


@app.route('/api/nmap/<string:query>')
@app.route('/api/nmap/<string:query>/<netmask>')
def get_nmap_port(query, netmask=32):
    """
    Scans host or whole subnet for hosts and their open ports. Uses NMAP's **-T4 -F** params to probe hosts.
    Probing is done from Hosting machine and therefore not suitable for scanning local network ranges.

    :param query: IP address or hostname
    :param netmask: (Optional) If you want to scan the whole range of hosts

    **Example:**

        $ GET ``/api/nmap/199.16.156.102/30``

        Returns::


            {
              "hosts": [
                {
                  "host": "199.16.156.102",
                  "status": {
                    "addresses": {
                      "ipv4": "199.16.156.102"
                    },
                    "hostnames": [],
                    "status": {
                      "reason": "syn-ack",
                      "state": "up"
                    },
                    "tcp": {
                      "80": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "http",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      },
                      "443": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "https",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      },
                      "8888": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "sun-answerbook",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      }
                    },
                    "vendor": {}
                  }
                },
                {
                  "host": "199.16.156.103",
                  "status": {
                    "addresses": {
                      "ipv4": "199.16.156.103"
                    },
                    "hostnames": [],
                    "status": {
                      "reason": "syn-ack",
                      "state": "up"
                    },
                    "tcp": {
                      "80": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "http",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      },
                      "443": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "https",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      },
                      "8888": {
                        "conf": "3",
                        "cpe": "",
                        "extrainfo": "",
                        "name": "sun-answerbook",
                        "product": "",
                        "reason": "syn-ack",
                        "state": "open",
                        "version": ""
                      }
                    },
                    "vendor": {}
                  }
                }
              ],
              "status": "ok"
            }
    """
    try:
        nm = nmap.PortScanner()
        hosts = dict()

        hosts['hosts'] = []
        if netmask == "":
            to_query = query
        else:
            to_query = query + "/" + str(netmask)

        logger.debug(to_query)

        try:
            net = IPNetwork(to_query)
        except AddrFormatError:
            abort(400)

        if net.is_link_local() or net.is_private():  # Won't scan server's local network
            abort(400)

        nm.scan(hosts=to_query, arguments='-T4 -F')
        hosts_list = [(x, nm[x]) for x in nm.all_hosts()]

        logger.debug(hosts_list)

        for host, status in hosts_list:
            hosts['hosts'].append({'host': host,
                                   'status': status})

        return jsonify({'status': "ok",
                        'hosts': hosts['hosts']})

    except nmap.PortScannerError:
        return error_response("NMAP error, cannot scan", 500)


@app.route('/api/ipcalc/<string:query>')
@app.route('/api/ipcalc/<string:query>/<string:netmask>')
def get_ipcalc_network(query, netmask=""):
    """
    IP calculator tool: supports IPv6 and IPv4 networks. For list of values see below.

    IP list is optional since it will return many IPs for some subnets,
    if you need to show ip list you will have to append ``?iplist`` to your get request.

    **PLEASE NOTE:** iplist will print only 65536 addresses which is /16 in IPv4 subnetting or /112 in IPv6 subnetting.
    If you try to get more you will get an error.

    :param query: IP address or hostname
    :param netmask: (Optional) If you want the whole range of hosts

    **Example:**

        When getting single host

        $ GET ``/api/ipcalc/199.16.156.102/30``

        ::


            {
              "results": {
                "broadcast": "199.16.156.103",
                "cidr": "199.16.156.100/30",
                "first_host": "199.16.156.101",
                "hostmask": "0.0.0.3",
                "ip_bits": "11000111.00010000.10011100.01100110",
                "ip_version": 4,
                "is_linklocal": false,
                "is_loopback": false,
                "is_multicast": false,
                "is_private": false,
                "is_public": true,
                "is_reserved": false,
                "is_unicast": true,
                "last_host": "199.16.156.102",
                "netmask": "255.255.255.252",
                "netmask_bits": "11111111.11111111.11111111.11111100",
                "network": "199.16.156.100",
                "network_bits": "11000111.00010000.10011100.01100100",
                "num_addresses": 4,
                "prefixlen": 30,
                "supernet": [
                  "0.0.0.0/0",
                  "128.0.0.0/1",
                  "192.0.0.0/2",
                  "192.0.0.0/3",
                  "192.0.0.0/4",
                  "192.0.0.0/5",
                  "196.0.0.0/6",
                  "198.0.0.0/7",
                  "199.0.0.0/8",
                  "199.0.0.0/9",
                  "199.0.0.0/10",
                  "199.0.0.0/11",
                  "199.16.0.0/12",
                  "199.16.0.0/13",
                  "199.16.0.0/14",
                  "199.16.0.0/15",
                  "199.16.0.0/16",
                  "199.16.128.0/17",
                  "199.16.128.0/18",
                  "199.16.128.0/19",
                  "199.16.144.0/20",
                  "199.16.152.0/21",
                  "199.16.156.0/22",
                  "199.16.156.0/23",
                  "199.16.156.0/24",
                  "199.16.156.0/25",
                  "199.16.156.64/26",
                  "199.16.156.96/27",
                  "199.16.156.96/28",
                  "199.16.156.96/29"
                ],
                "to_ipv6": "::ffff:199.16.156.102/126"
              },
              "status": "ok"
            }

    """

    if netmask is not "":
        ip = query + '/' + netmask
    else:
        ip = query

    try:
        net = IPNetwork(ip)
    except AddrFormatError:
        abort(400)

    results = dict()
    results['broadcast'] = str(net.broadcast)
    results['network'] = str(net.network)
    results['netmask'] = str(net.netmask)
    results['cidr'] = str(net.cidr)
    results['num_addresses'] = net.size
    results['hostmask'] = str(net.hostmask)
    results['is_loopback'] = net.is_loopback()
    results['is_unicast'] = net.is_unicast()
    results['is_multicast'] = net.is_multicast()
    results['is_private'] = net.is_private()
    results['is_reserved'] = net.is_reserved()
    results['is_linklocal'] = net.is_link_local()
    results['is_public'] = net.is_unicast() and not net.is_private()
    results['prefixlen'] = net.prefixlen
    results['ip_version'] = net.version
    results['ip_bits'] = net.ip.bits()
    results['network_bits'] = net.network.bits()
    results['netmask_bits'] = net.netmask.bits()
    results['supernet'] = [str(supernet) for supernet in net.supernet()]

    if net.version == 4:
        results['to_ipv6'] = str(net.ipv6())

        if request.query_string == 'iplist':
            if net.size <= 65536:
                results['ip_list'] = [str(ip) for ip in list(net)]
            else:
                return error_response("Too many IPs to list (limit is 65536), "
                                      "use smaller subnet or remove '?iplist' from query.", 400)

        if net.broadcast is not None:
            results['first_host'] = str(net.network + 1)
            results['last_host'] = str(net.broadcast - 1)
        else:
            results['first_host'] = str(net.ip)
            results['last_host'] = str(net.ip)

    elif net.version == 6:
        try:
            results['to_ipv4'] = str(net.ipv4())
        except AddrConversionError:
            results['to_ipv4'] = None

        if request.query_string == 'iplist':
            if net.size <= 65536:
                results['ip_list'] = [str(ip) for ip in list(net)]
            else:
                return error_response("Too many IPs to list (limit is 65536), "
                                      "use smaller subnet or remove '?iplist' from query.", 400)

    return jsonify({'status': "ok",
                    'results': results})
