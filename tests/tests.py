import sys
print sys.path

import unittest
import networktoolsapi
import json


class TestNetworkToolsAPI(unittest.TestCase):

    def setUp(self):
        networktoolsapi.app.config['TESTING'] = True
        self.app = networktoolsapi.app.test_client()

    def test_resolver(self):
        rv = networktoolsapi.api.hostname_resolves('example.com')
        self.assertEqual(rv, ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])

    def test_geoip_public_domain(self):
        rv = self.app.get('/api/geoip/example.com', environ_base={'REMOTE_ADDR': '93.184.216.34'})
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('geoip', resp)
        self.assertIn('resolved_ips', resp)
        self.assertIn('status', resp)
        self.assertIn('isp', resp['geoip'][0])
        self.assertIn('ip', resp['geoip'][0])
        self.assertIn('latitude', resp['geoip'][0])
        self.assertIn('longitude', resp['geoip'][0])
        self.assertIn('distance', resp['geoip'][0])
        self.assertIn('distance_unit', resp['geoip'][0])
        self.assertIsInstance(resp['resolved_ips'], list)

    def test_geoip_public_domain_imperial(self):
        rv = self.app.get('/api/geoip/example.com?imperial', environ_base={'REMOTE_ADDR': '93.184.216.34'})
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('distance', resp['geoip'][0])
        self.assertIn('distance_unit', resp['geoip'][0])
        self.assertEqual('mi', resp['geoip'][0]['distance_unit'])
        self.assertIsInstance(resp['resolved_ips'], list)

    def test_geoip_public_ip(self):
        rv = self.app.get('/api/geoip/8.8.8.8', environ_base={'REMOTE_ADDR': '93.184.216.34'})
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('geoip', resp)
        self.assertIn('resolved_ips', rv.data)
        self.assertIn('status', rv.data)
        self.assertIn('isp', resp['geoip'][0])
        self.assertIn('ip', resp['geoip'][0])
        self.assertIn('latitude', resp['geoip'][0])
        self.assertIn('longitude', resp['geoip'][0])
        self.assertIn('distance', resp['geoip'][0])
        self.assertIn('distance_unit', resp['geoip'][0])
        self.assertIsInstance(resp['resolved_ips'], list)

    def test_geoip_public_ip_imperial(self):
        rv = self.app.get('/api/geoip/8.8.8.8?imperial', environ_base={'REMOTE_ADDR': '93.184.216.34'})
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('distance', resp['geoip'][0])
        self.assertIn('distance_unit', resp['geoip'][0])
        self.assertEqual('mi', resp['geoip'][0]['distance_unit'])
        self.assertIsInstance(resp['resolved_ips'], list)

    def test_geoip_private_ip(self):
        rv = self.app.get('/api/geoip/192.168.0.1')
        self.assertEqual(rv.status_code, 400)

    def test_geoip_garbage(self):
        rv = self.app.get('/api/geoip/agagdsdgsgsgs.com')
        self.assertEqual(rv.status_code, 400)

    def test_ipwhois_public_domain(self):
        rv = self.app.get('/api/ipwhois/example.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('ipwhois', resp)
        self.assertIn('status', resp)
        self.assertIn('query', resp['ipwhois'][0])
        self.assertIn('asn', resp['ipwhois'][0])
        self.assertIn('nets', resp['ipwhois'][0])
        self.assertIsInstance(resp['ipwhois'][0]['nets'], list)
        self.assertIn('name', resp['ipwhois'][0]['nets'][0])
        self.assertIn('city', resp['ipwhois'][0]['nets'][0])
        self.assertIn('cidr', resp['ipwhois'][0]['nets'][0])
        self.assertIn('address', resp['ipwhois'][0]['nets'][0])
        self.assertIn('country', resp['ipwhois'][0]['nets'][0])
        self.assertIsInstance(resp['ipwhois'], list)

    def test_ipwhois_public_ip(self):
        rv = self.app.get('/api/ipwhois/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('ipwhois', resp)
        self.assertIn('status', resp)
        self.assertIn('query', resp['ipwhois'][0])
        self.assertIn('asn', resp['ipwhois'][0])
        self.assertIn('nets', resp['ipwhois'][0])
        self.assertIsInstance(resp['ipwhois'][0]['nets'], list)
        self.assertIn('name', resp['ipwhois'][0]['nets'][0])
        self.assertIn('city', resp['ipwhois'][0]['nets'][0])
        self.assertIn('cidr', resp['ipwhois'][0]['nets'][0])
        self.assertIn('address', resp['ipwhois'][0]['nets'][0])
        self.assertIn('country', resp['ipwhois'][0]['nets'][0])
        self.assertIsInstance(resp['ipwhois'], list)

    def test_ipwhois_private_ip(self):
        rv = self.app.get('/api/ipwhois/192.168.0.1')
        self.assertEqual(rv.status_code, 400)

    def test_ipwhois_garbage(self):
        rv = self.app.get('/api/ipwhois/agagdsdgsgsgs.com')
        self.assertEqual(rv.status_code, 400)

    def test_whois_public_domain(self):
        rv = self.app.get('/api/whois/example.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('whois', resp)
        self.assertIn('status', resp)
        self.assertIn('contacts', resp['whois'])
        self.assertIn('admin', resp['whois']['contacts'])
        self.assertIn('billing', resp['whois']['contacts'])
        self.assertIn('registrant', resp['whois']['contacts'])
        self.assertIn('tech', resp['whois']['contacts'])
        self.assertIn('updated_date', resp['whois'])
        self.assertIsInstance(resp['whois']['raw'], list)

    def test_whois_public_ip(self):
        rv = self.app.get('/api/whois/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('whois', resp)
        self.assertIn('status', resp)
        self.assertIn('contacts', resp['whois'])
        self.assertIn('admin', resp['whois']['contacts'])
        self.assertIn('billing', resp['whois']['contacts'])
        self.assertIn('registrant', resp['whois']['contacts'])
        self.assertIn('tech', resp['whois']['contacts'])
        self.assertIsInstance(resp['whois']['raw'], list)

    def test_whois_private_ip(self):
        rv = self.app.get('/api/whois/192.168.0.1')
        self.assertEqual(rv.status_code, 400)

    def test_whois_garbage(self):
        rv = self.app.get('/api/whois/kahkshkjgsha')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_whois_garbage_valid_tld(self):
        rv = self.app.get('/api/whois/kahkshkjgsha.com')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'ok')
        self.assertEqual(rv.status_code, 200)

    def test_whois_garbage_invalid_tld(self):
        rv = self.app.get('/api/whois/kahkshkjgsha.tlapi')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(resp['msg'], "No root WHOIS server found for domain.")
        self.assertEqual(rv.status_code, 400)

    def test_dns_public_domain(self):
        rv = self.app.get('/api/dns/google.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('status', resp)
        self.assertIn('mx', resp)
        self.assertIn('ns', resp)
        self.assertIn('soa', resp)
        self.assertIn('txt', resp)
        
        self.assertIsInstance(resp['hosts']['records'], list)
        self.assertIsInstance(resp['hosts']['records'], list)
        self.assertIsInstance(resp['ns']['records'], list)
        self.assertIsInstance(resp['txt']['records'], list)
        self.assertIsInstance(resp['soa']['records'], list)

    def test_dns_public_ip(self):
        rv = self.app.get('/api/dns/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(resp['msg'], "Non-existent Domain Name (NXDOMAIN)")
        self.assertEqual(resp['status'], "error")

    def test_dns_private_ip(self):
        rv = self.app.get('/api/dns/192.168.0.1')
        self.assertEqual(rv.status_code, 400)

    def test_dns_garbage(self):
        rv = self.app.get('/api/dns/kahkshkjgsha')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_dns_public_domain_custom_valid_querier(self):
        rv = self.app.get('/api/dns/example.com?q=209.244.0.3')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('status', resp)
        self.assertIn('mx', resp)
        self.assertIn('ns', resp)
        self.assertIn('soa', resp)
        self.assertIn('txt', resp)

        self.assertIsInstance(resp['hosts']['records'], list)
        self.assertIsInstance(resp['hosts']['records'], list)
        self.assertIsInstance(resp['ns']['records'], list)
        self.assertIsInstance(resp['txt']['records'], list)
        self.assertIsInstance(resp['soa']['records'], list)

    def test_dns_public_domain_custom_invalid_querier(self):
        rv = self.app.get('/api/dns/example.com?q=1.1.1.1')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(resp['msg'], "Request timed out")
        self.assertEqual(resp['status'], "error")

    def test_dns_public_domain_custom_no_querier(self):
        rv = self.app.get('/api/dns/example.com?q=')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(resp['msg'], "Request timed out")
        self.assertEqual(resp['status'], "error")

    # HOST
    def test_host_public_domain(self):
        rv = self.app.get('/api/host/example.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(resp['status'], 'error')

    def test_host_public_ip(self):
        rv = self.app.get('/api/host/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('up', resp)
        self.assertIn('down', resp)
        self.assertIn('status', resp)
        self.assertIsInstance(resp['hosts'], list)

    def test_host_public_ip_range(self):
        rv = self.app.get('/api/host/8.8.8.8/28')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('up', resp)
        self.assertIn('down', resp)
        self.assertIn('status', resp)
        self.assertIsInstance(resp['hosts'], list)

    def test_host_private_ip(self):
        rv = self.app.get('/api/host/192.168.0.1')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_host_private_ip_range(self):
        rv = self.app.get('/api/host/192.168.0.1/29')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_host_garbage(self):
        rv = self.app.get('/api/host/kahkshkjgsha')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    # NMAP
    def test_nmap_public_domain(self):
        rv = self.app.get('/api/nmap/example.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(resp['status'], 'error')

    def test_nmap_public_unscannable_ip(self):
        rv = self.app.get('/api/nmap/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('status', resp)
        self.assertEqual(resp['status'], 'ok')

    def test_nmap_public_ip(self):
        rv = self.app.get('/api/nmap/95.180.1.211')  # Sorry google-cache :)
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('status', resp)
        self.assertIn('host', resp['hosts'][0])
        self.assertIn('status', resp['hosts'][0])
        self.assertIn('addresses', resp['hosts'][0]['status'])
        self.assertIn('hostnames', resp['hosts'][0]['status'])
        self.assertIn('status', resp['hosts'][0]['status'])
        self.assertIn('tcp', resp['hosts'][0]['status'])
        self.assertIsInstance(resp['hosts'], list)

    def test_nmap_public_ip_range(self):
        rv = self.app.get('/api/nmap/95.180.1.211/28')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('hosts', resp)
        self.assertIn('status', resp)
        self.assertIn('host', resp['hosts'][0])
        self.assertIn('status', resp['hosts'][0])
        self.assertIn('addresses', resp['hosts'][0]['status'])
        self.assertIn('hostnames', resp['hosts'][0]['status'])
        self.assertIn('status', resp['hosts'][0]['status'])
        self.assertIn('tcp', resp['hosts'][0]['status'])
        self.assertIsInstance(resp['hosts'], list)

    def test_nmap_private_ip(self):
        rv = self.app.get('/api/nmap/192.168.0.1')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_nmap_private_ip_range(self):
        rv = self.app.get('/api/nmap/192.168.0.1/29')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_nmap_garbage(self):
        rv = self.app.get('/api/nmap/kahkshkjgsha')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)


    # ipcalc
    def test_ipcalc_public_domain(self):
        rv = self.app.get('/api/ipcalc/example.com')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(resp['status'], 'error')

    def test_ipcalc_public_ip(self):
        rv = self.app.get('/api/ipcalc/8.8.8.8')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('results', resp)
        self.assertIn('status', resp)
        self.assertIn('broadcast', resp['results'])
        self.assertIn('cidr', resp['results'])
        self.assertIn('first_host', resp['results'])
        self.assertIn('hostmask', resp['results'])
        self.assertIn('last_host', resp['results'])
        self.assertIn('netmask', resp['results'])
        self.assertIn('network', resp['results'])
        self.assertIn('num_addresses', resp['results'])
        self.assertIn('prefixlen', resp['results'])
        self.assertIn('supernet', resp['results'])

    def test_ipcalc_public_ip_range(self):
        rv = self.app.get('/api/ipcalc/8.8.8.8/28')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('results', resp)
        self.assertIn('status', resp)
        self.assertIn('broadcast', resp['results'])
        self.assertIn('cidr', resp['results'])
        self.assertIn('first_host', resp['results'])
        self.assertIn('hostmask', resp['results'])
        self.assertIn('last_host', resp['results'])
        self.assertIn('netmask', resp['results'])
        self.assertIn('network', resp['results'])
        self.assertIn('num_addresses', resp['results'])
        self.assertIn('prefixlen', resp['results'])
        self.assertIn('supernet', resp['results'])

    def test_ipcalc_private_ip(self):
        rv = self.app.get('/api/ipcalc/192.168.0.1')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('results', resp)
        self.assertIn('status', resp)
        self.assertIn('broadcast', resp['results'])
        self.assertIn('cidr', resp['results'])
        self.assertIn('first_host', resp['results'])
        self.assertIn('hostmask', resp['results'])
        self.assertIn('last_host', resp['results'])
        self.assertIn('netmask', resp['results'])
        self.assertIn('network', resp['results'])
        self.assertIn('num_addresses', resp['results'])
        self.assertIn('prefixlen', resp['results'])
        self.assertIn('supernet', resp['results'])

    def test_ipcalc_private_ip_range(self):
        rv = self.app.get('/api/ipcalc/192.168.0.1/29')
        resp = json.loads(rv.data)
        self.assertEqual(rv.status_code, 200)
        self.assertIn('results', resp)
        self.assertIn('status', resp)
        self.assertIn('broadcast', resp['results'])
        self.assertIn('cidr', resp['results'])
        self.assertIn('first_host', resp['results'])
        self.assertIn('hostmask', resp['results'])
        self.assertIn('last_host', resp['results'])
        self.assertIn('netmask', resp['results'])
        self.assertIn('network', resp['results'])
        self.assertIn('num_addresses', resp['results'])
        self.assertIn('prefixlen', resp['results'])
        self.assertIn('supernet', resp['results'])

    def test_ipcalc_garbage_domain(self):
        rv = self.app.get('/api/ipcalc/kahkshkjgsha')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

    def test_ipcalc_garbage_ip(self):
        rv = self.app.get('/api/ipcalc/256.444.233.123')
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'error')
        self.assertEqual(rv.status_code, 400)

if __name__ == '__main__':
    unittest.main()
