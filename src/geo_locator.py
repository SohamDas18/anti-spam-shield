# -*- coding: utf-8 -*-
"""
Geographic Origin & Threat Vector Location Intelligence Engine
Determines the physical geographic origin, telecom circle, hosting country,
and server coordinates of:
1. Sender Phone Numbers & International Callers
2. TRAI Telecom SMS Headers (India DLT shortcodes)
3. Sender Email Domains & Mail Server IP Addresses
4. Embedded URL Hosting Web Servers & Threat Vectors
"""

import re
import socket
import urllib.request
import json
import logging
from functools import lru_cache

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Country ISO codes, centroid coordinates, and flag emojis
COUNTRY_REGISTRY = {
    'IN': {'country': 'India', 'flag': '🇮🇳', 'lat': 20.5937, 'lon': 78.9629, 'risk': 'NORMAL'},
    'US': {'country': 'United States', 'flag': '🇺🇸', 'lat': 37.0902, 'lon': -95.7129, 'risk': 'NORMAL'},
    'GB': {'country': 'United Kingdom', 'flag': '🇬🇧', 'lat': 55.3781, 'lon': -3.4360, 'risk': 'NORMAL'},
    'CA': {'country': 'Canada', 'flag': '🇨🇦', 'lat': 56.1304, 'lon': -106.3468, 'risk': 'NORMAL'},
    'RU': {'country': 'Russia', 'flag': '🇷🇺', 'lat': 61.5240, 'lon': 105.3188, 'risk': 'ELEVATED'},
    'CN': {'country': 'China', 'flag': '🇨🇳', 'lat': 35.8617, 'lon': 104.1954, 'risk': 'ELEVATED'},
    'NG': {'country': 'Nigeria', 'flag': '🇳🇬', 'lat': 9.0820, 'lon': 8.6753, 'risk': 'HIGH'},
    'PK': {'country': 'Pakistan', 'flag': '🇵🇰', 'lat': 30.3753, 'lon': 69.3451, 'risk': 'HIGH'},
    'BD': {'country': 'Bangladesh', 'flag': '🇧🇩', 'lat': 23.6850, 'lon': 90.3563, 'risk': 'NORMAL'},
    'DE': {'country': 'Germany', 'flag': '🇩🇪', 'lat': 51.1657, 'lon': 10.4515, 'risk': 'NORMAL'},
    'FR': {'country': 'France', 'flag': '🇫🇷', 'lat': 46.2276, 'lon': 2.2137, 'risk': 'NORMAL'},
    'NL': {'country': 'Netherlands', 'flag': '🇳🇱', 'lat': 52.1326, 'lon': 5.2913, 'risk': 'NORMAL'},
    'SG': {'country': 'Singapore', 'flag': '🇸🇬', 'lat': 1.3521, 'lon': 103.8198, 'risk': 'NORMAL'},
    'AE': {'country': 'United Arab Emirates', 'flag': '🇦🇪', 'lat': 23.4241, 'lon': 53.8478, 'risk': 'NORMAL'},
    'AU': {'country': 'Australia', 'flag': '🇦🇺', 'lat': -25.2744, 'lon': 133.7751, 'risk': 'NORMAL'},
    'JP': {'country': 'Japan', 'flag': '🇯🇵', 'lat': 36.2048, 'lon': 138.2529, 'risk': 'NORMAL'},
    'KE': {'country': 'Kenya', 'flag': '🇰🇪', 'lat': -0.0236, 'lon': 37.9062, 'risk': 'ELEVATED'},
    'PH': {'country': 'Philippines', 'flag': '🇵🇭', 'lat': 12.8797, 'lon': 121.7740, 'risk': 'NORMAL'},
    'ID': {'country': 'Indonesia', 'flag': '🇮🇩', 'lat': -0.7893, 'lon': 113.9213, 'risk': 'NORMAL'},
    'BR': {'country': 'Brazil', 'flag': '🇧🇷', 'lat': -14.2350, 'lon': -51.9253, 'risk': 'NORMAL'},
    'ZA': {'country': 'South Africa', 'flag': '🇿🇦', 'lat': -30.5595, 'lon': 22.9375, 'risk': 'NORMAL'}
}

# Indian Telecom Circles for TRAI SMS Headers (e.g. VK-HDFCBK -> V=Vodafone, K=Kolkata)
TRAI_OPERATORS = {
    'A': 'Bharti Airtel',
    'B': 'BSNL',
    'J': 'Reliance Jio',
    'V': 'Vodafone Idea (Vi)',
    'T': 'Tata Teleservices',
    'M': 'MTNL'
}

TRAI_CIRCLES = {
    'K': {'city': 'Kolkata', 'state': 'West Bengal', 'lat': 22.5726, 'lon': 88.3639},
    'W': {'city': 'Kolkata / Siliguri', 'state': 'West Bengal (Rest of WB)', 'lat': 22.9868, 'lon': 87.8550},
    'D': {'city': 'New Delhi', 'state': 'Delhi NCR', 'lat': 28.7041, 'lon': 77.1025},
    'M': {'city': 'Mumbai', 'state': 'Maharashtra', 'lat': 19.0760, 'lon': 72.8777},
    'S': {'city': 'Pune / Nagpur', 'state': 'Maharashtra & Goa', 'lat': 19.7515, 'lon': 75.7139},
    'B': {'city': 'Bengaluru', 'state': 'Karnataka', 'lat': 12.9716, 'lon': 77.5946},
    'C': {'city': 'Chennai', 'state': 'Tamil Nadu', 'lat': 13.0827, 'lon': 80.2707},
    'T': {'city': 'Coimbatore / Madurai', 'state': 'Tamil Nadu', 'lat': 11.1271, 'lon': 78.6569},
    'A': {'city': 'Hyderabad', 'state': 'Telangana & Andhra Pradesh', 'lat': 15.9129, 'lon': 79.7400},
    'G': {'city': 'Ahmedabad', 'state': 'Gujarat', 'lat': 22.2587, 'lon': 71.1924},
    'H': {'city': 'Gurugram / Faridabad', 'state': 'Haryana', 'lat': 29.0588, 'lon': 76.0856},
    'P': {'city': 'Chandigarh / Ludhiana', 'state': 'Punjab', 'lat': 31.1471, 'lon': 75.3412},
    'R': {'city': 'Jaipur', 'state': 'Rajasthan', 'lat': 27.0238, 'lon': 74.2179},
    'E': {'city': 'Lucknow / Varanasi', 'state': 'UP East', 'lat': 26.8467, 'lon': 80.9462},
    'U': {'city': 'Noida / Meerut / Agra', 'state': 'UP West', 'lat': 28.9845, 'lon': 77.7064},
    'I': {'city': 'Patna / Ranchi', 'state': 'Bihar & Jharkhand', 'lat': 25.0961, 'lon': 85.3131},
    'O': {'city': 'Bhubaneswar', 'state': 'Odisha', 'lat': 20.9517, 'lon': 85.0985},
    'X': {'city': 'Kochi / Thiruvananthapuram', 'state': 'Kerala', 'lat': 10.8505, 'lon': 76.2711},
    'Z': {'city': 'Guwahati', 'state': 'Assam', 'lat': 26.2006, 'lon': 92.9376},
    'N': {'city': 'Shillong / Agartala', 'state': 'North East', 'lat': 25.5788, 'lon': 91.8933}
}

# Indian Mobile Number Prefix to Circle Mapping (first 4 digits of 10-digit number)
INDIAN_MOBILE_PREFIX_MAP = {
    # Kolkata & WB
    '9830': TRAI_CIRCLES['K'], '9831': TRAI_CIRCLES['K'], '9832': TRAI_CIRCLES['W'],
    '9836': TRAI_CIRCLES['K'], '9433': TRAI_CIRCLES['K'], '9434': TRAI_CIRCLES['W'],
    '9051': TRAI_CIRCLES['K'], '9874': TRAI_CIRCLES['K'], '9875': TRAI_CIRCLES['K'],
    # Mumbai
    '9820': TRAI_CIRCLES['M'], '9821': TRAI_CIRCLES['M'], '9819': TRAI_CIRCLES['M'],
    '9833': TRAI_CIRCLES['M'], '9892': TRAI_CIRCLES['M'], '9322': TRAI_CIRCLES['M'],
    # Delhi NCR
    '9810': TRAI_CIRCLES['D'], '9811': TRAI_CIRCLES['D'], '9818': TRAI_CIRCLES['D'],
    '9871': TRAI_CIRCLES['D'], '9873': TRAI_CIRCLES['D'], '9891': TRAI_CIRCLES['D'],
    '9899': TRAI_CIRCLES['D'], '9910': TRAI_CIRCLES['D'], '9911': TRAI_CIRCLES['D'],
    # Karnataka / Bangalore
    '9845': TRAI_CIRCLES['B'], '9844': TRAI_CIRCLES['B'], '9880': TRAI_CIRCLES['B'],
    '9886': TRAI_CIRCLES['B'], '9900': TRAI_CIRCLES['B'], '9945': TRAI_CIRCLES['B'],
    # Chennai / Tamil Nadu
    '9840': TRAI_CIRCLES['C'], '9841': TRAI_CIRCLES['C'], '9884': TRAI_CIRCLES['C'],
    '9940': TRAI_CIRCLES['C'], '9842': TRAI_CIRCLES['T'], '9843': TRAI_CIRCLES['T'],
    # AP / Telangana
    '9848': TRAI_CIRCLES['A'], '9849': TRAI_CIRCLES['A'], '9866': TRAI_CIRCLES['A'],
    '9885': TRAI_CIRCLES['A'], '9948': TRAI_CIRCLES['A'], '9949': TRAI_CIRCLES['A'],
    # Maharashtra & Goa
    '9822': TRAI_CIRCLES['S'], '9823': TRAI_CIRCLES['S'], '9850': TRAI_CIRCLES['S'],
    '9881': TRAI_CIRCLES['S'], '9890': TRAI_CIRCLES['S'], '9922': TRAI_CIRCLES['S'],
    # Gujarat
    '9824': TRAI_CIRCLES['G'], '9825': TRAI_CIRCLES['G'], '9879': TRAI_CIRCLES['G'],
    '9898': TRAI_CIRCLES['G'], '9904': TRAI_CIRCLES['G'], '9925': TRAI_CIRCLES['G'],
    # Punjab
    '9814': TRAI_CIRCLES['P'], '9815': TRAI_CIRCLES['P'], '9855': TRAI_CIRCLES['P'],
    '9872': TRAI_CIRCLES['P'], '9876': TRAI_CIRCLES['P'], '9878': TRAI_CIRCLES['P'],
    # Rajasthan
    '9829': TRAI_CIRCLES['R'], '9828': TRAI_CIRCLES['R'], '9887': TRAI_CIRCLES['R'],
    # Haryana
    '9812': TRAI_CIRCLES['H'], '9813': TRAI_CIRCLES['H'], '9896': TRAI_CIRCLES['H'],
    # UP East
    '9838': TRAI_CIRCLES['E'], '9839': TRAI_CIRCLES['E'], '9889': TRAI_CIRCLES['E'],
    # UP West
    '9837': TRAI_CIRCLES['U'], '9897': TRAI_CIRCLES['U'], '9917': TRAI_CIRCLES['U'],
    # Bihar & Jharkhand
    '9835': TRAI_CIRCLES['I'], '9852': TRAI_CIRCLES['I'], '9934': TRAI_CIRCLES['I'],
    # Kerala
    '9846': TRAI_CIRCLES['X'], '9847': TRAI_CIRCLES['X'], '9895': TRAI_CIRCLES['X'],
    # Odisha
    '9861': TRAI_CIRCLES['O'], '9937': TRAI_CIRCLES['O'],
    # Assam
    '9864': TRAI_CIRCLES['Z'], '9954': TRAI_CIRCLES['Z']
}

# Cache for IP lookups to avoid external calls
_IP_GEO_CACHE = {}

def geolocate_ip_or_host(host_or_ip):
    """
    Resolves domain hostname to IP and queries IP geolocation API.
    Returns dict with country, city, coordinates, and ISP.
    """
    if not host_or_ip:
        return None
    
    clean_host = host_or_ip.strip().lower()
    # Strip protocols if present
    clean_host = re.sub(r'^https?://', '', clean_host).split('/')[0].split(':')[0]
    
    if clean_host in _IP_GEO_CACHE:
        return _IP_GEO_CACHE[clean_host]
    
    # Check if local/private
    if clean_host in ['localhost', '127.0.0.1', '0.0.0.0'] or clean_host.startswith('192.168.') or clean_host.startswith('10.'):
        res = {
            'status': 'success',
            'country': 'Localhost / Private Network',
            'countryCode': 'IN',
            'flag': '💻',
            'regionName': 'Local Development',
            'city': 'Internal Loopback',
            'lat': 20.5937,
            'lon': 78.9629,
            'isp': 'Localhost Service',
            'ip': clean_host
        }
        _IP_GEO_CACHE[clean_host] = res
        return res

    # 1. DNS Resolution
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(clean_host)
    except Exception:
        resolved_ip = None

    target_ip = resolved_ip if resolved_ip else clean_host

    # 2. Query Geolocation Service (ip-api.com, free, up to 45 req/min, 1.5s timeout)
    try:
        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'SentinelAI-Threat-Geo/2.0'})
        with urllib.request.urlopen(req, timeout=1.8) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('status') == 'success':
                cc = data.get('countryCode', 'US')
                flag = COUNTRY_REGISTRY.get(cc, {}).get('flag', '🌐')
                data['flag'] = flag
                data['ip'] = target_ip
                if len(_IP_GEO_CACHE) > 500:
                    _IP_GEO_CACHE.clear()
                _IP_GEO_CACHE[clean_host] = data
                return data
    except Exception as e:
        logger.warning(f"Geo IP lookup failed for {target_ip}: {e}")

    # Fallback to TLD / Domain Heuristics if API unavailable
    tld_match = clean_host.split('.')[-1]
    fallback_cc = tld_match.upper() if tld_match.upper() in COUNTRY_REGISTRY else 'US'
    country_info = COUNTRY_REGISTRY.get(fallback_cc, COUNTRY_REGISTRY['US'])
    
    fallback_data = {
        'status': 'success',
        'country': country_info['country'],
        'countryCode': fallback_cc,
        'flag': country_info['flag'],
        'regionName': 'Global Region',
        'city': 'Primary Gateway',
        'lat': country_info['lat'],
        'lon': country_info['lon'],
        'isp': 'Domain DNS Host',
        'ip': target_ip
    }
    _IP_GEO_CACHE[clean_host] = fallback_data
    return fallback_data


def locate_sender(sender, message_type='AUTO'):
    """
    Dissects the sender identifier to identify physical geographic origin,
    telecom carrier, regulatory header registration, or mail server hosting.
    """
    if not sender or not sender.strip():
        return {
            'source_type': 'UNKNOWN SENDER',
            'identifier': 'Unknown',
            'country': 'Unknown Location',
            'flag': '❓',
            'region_city': 'Origin Hidden',
            'carrier_or_isp': 'Unresolved',
            'lat': 20.0,
            'lon': 0.0,
            'is_foreign': False,
            'risk_note': 'No sender details provided.'
        }

    clean_sender = sender.strip()

    # 1. Check if Email Address
    if '@' in clean_sender:
        domain = clean_sender.split('@')[-1].lower()
        geo = geolocate_ip_or_host(domain)
        country = geo.get('country', 'Unknown')
        flag = geo.get('flag', '🌐')
        city = geo.get('city', '')
        region = geo.get('regionName', '')
        loc_str = f"{city}, {region}".strip(', ') if (city or region) else country
        isp = geo.get('isp', 'Mail Exchanger Host')
        lat = geo.get('lat', 37.0902)
        lon = geo.get('lon', -95.7129)
        cc = geo.get('countryCode', 'US')

        is_foreign = cc != 'IN'
        risk_note = None
        if is_foreign and any(b in domain for b in ['sbi', 'hdfc', 'icici', 'axis', 'paytm', 'bspc', 'wbse']):
            risk_note = f"CRITICAL: Foreign mail server ({country} {flag}) spoofing domestic Indian institution!"

        return {
            'source_type': 'EMAIL MAIL SERVER',
            'identifier': clean_sender,
            'domain_or_host': domain,
            'country': country,
            'country_code': cc,
            'flag': flag,
            'region_city': loc_str or country,
            'carrier_or_isp': isp,
            'lat': lat,
            'lon': lon,
            'ip_address': geo.get('ip', 'Unresolved'),
            'is_foreign': is_foreign,
            'risk_note': risk_note,
            'map_color': '#ef4444' if risk_note else '#06b6d4'
        }

    # 2. Check if TRAI Indian SMS Shortcode (e.g. VK-HDFCBK, AD-SBIINB)
    trai_match = re.match(r'^([A-Z])([A-Z])-([A-Z0-9]{4,6})$', clean_sender, re.IGNORECASE)
    if trai_match:
        op_code = trai_match.group(1).upper()
        circle_code = trai_match.group(2).upper()
        entity = trai_match.group(3).upper()

        op_name = TRAI_OPERATORS.get(op_code, f"Telecom Gateway ({op_code})")
        circle_info = TRAI_CIRCLES.get(circle_code, {'city': 'Telecom Gateway', 'state': 'India', 'lat': 20.5937, 'lon': 78.9629})

        return {
            'source_type': 'TRAI DLT SMS SHORTCODE',
            'identifier': clean_sender,
            'registered_entity': entity,
            'country': 'India',
            'country_code': 'IN',
            'flag': '🇮🇳',
            'region_city': f"{circle_info['city']}, {circle_info['state']}",
            'carrier_or_isp': op_name,
            'lat': circle_info['lat'],
            'lon': circle_info['lon'],
            'is_foreign': False,
            'risk_note': None,
            'map_color': '#10b981' # Green (Official registered DLT gateway)
        }

    # 3. Check Phone Number
    digits = re.sub(r'\D', '', clean_sender)
    
    # Try libphonenumber parsing
    if PHONENUMBERS_AVAILABLE and len(digits) >= 7:
        try:
            # If standard 10 digit Indian number without country code
            raw_input = clean_sender
            if len(digits) == 10 and digits[0] in '6789' and not clean_sender.startswith('+'):
                raw_input = f"+91{digits}"
            elif not raw_input.startswith('+'):
                raw_input = f"+{raw_input}"

            parsed = phonenumbers.parse(raw_input, None)
            if phonenumbers.is_valid_number(parsed):
                country_name = geocoder.description_for_number(parsed, 'en') or "Global"
                carr_name = carrier.name_for_number(parsed, 'en') or "Mobile Network"
                country_code_num = str(parsed.country_code)

                # Determine country code string
                cc_str = 'IN' if country_code_num == '91' else ('US' if country_code_num == '1' else ('GB' if country_code_num == '44' else ('NG' if country_code_num == '234' else 'US')))
                country_meta = COUNTRY_REGISTRY.get(cc_str, {'flag': '🌐', 'lat': 20.0, 'lon': 0.0})

                lat = country_meta['lat']
                lon = country_meta['lon']
                flag = country_meta['flag']
                region_city = country_name

                # If Indian number, refine to circle level
                if country_code_num == '91':
                    num_10 = digits[-10:]
                    prefix_4 = num_10[:4]
                    if prefix_4 in INDIAN_MOBILE_PREFIX_MAP:
                        circle = INDIAN_MOBILE_PREFIX_MAP[prefix_4]
                        region_city = f"{circle['city']}, {circle['state']}"
                        lat = circle['lat']
                        lon = circle['lon']

                is_foreign = country_code_num != '91'
                risk_note = None
                if is_foreign and country_code_num in ['234', '92', '7']:
                    risk_note = f"HIGH RISK: Message origin from foreign high-risk telecom jurisdiction (+{country_code_num} {country_name})!"

                return {
                    'source_type': 'MOBILE / PHONE SENDER',
                    'identifier': clean_sender,
                    'country': country_name or "India",
                    'country_code': cc_str,
                    'flag': flag,
                    'region_city': region_city,
                    'carrier_or_isp': carr_name or "GSM Carrier",
                    'lat': lat,
                    'lon': lon,
                    'is_foreign': is_foreign,
                    'risk_note': risk_note,
                    'map_color': '#ef4444' if is_foreign else '#06b6d4'
                }
        except Exception:
            pass

    # Fallback for Indian 10 digit number
    if len(digits) == 10 and digits[0] in '6789':
        prefix = digits[:4]
        circle = INDIAN_MOBILE_PREFIX_MAP.get(prefix, {'city': 'National Mobile Network', 'state': 'India', 'lat': 20.5937, 'lon': 78.9629})
        return {
            'source_type': 'MOBILE NUMBER',
            'identifier': clean_sender,
            'country': 'India',
            'country_code': 'IN',
            'flag': '🇮🇳',
            'region_city': f"{circle['city']}, {circle['state']}",
            'carrier_or_isp': 'Indian Mobile Network',
            'lat': circle['lat'],
            'lon': circle['lon'],
            'is_foreign': False,
            'risk_note': None,
            'map_color': '#06b6d4'
        }

    # General fallback
    return {
        'source_type': 'UNVERIFIED SENDER',
        'identifier': clean_sender,
        'country': 'India / International',
        'country_code': 'IN',
        'flag': '🇮🇳',
        'region_city': 'Origin Carrier Unresolved',
        'carrier_or_isp': 'Telecommunications Carrier',
        'lat': 20.5937,
        'lon': 78.9629,
        'is_foreign': False,
        'risk_note': None,
        'map_color': '#94a3b8'
    }


def locate_url_hosts(url_objects):
    """Geolocates physical server hosting locations for embedded hyperlinks."""
    results = []
    if not url_objects:
        return results

    for u in url_objects:
        raw_url = u.get('url', '') if isinstance(u, dict) else str(u)
        host_match = re.search(r'https?://([^/:]+)', raw_url, re.IGNORECASE)
        host = host_match.group(1) if host_match else raw_url

        geo = geolocate_ip_or_host(host)
        if geo:
            results.append({
                'url': raw_url,
                'host': host,
                'country': geo.get('country', 'Unknown'),
                'country_code': geo.get('countryCode', 'US'),
                'flag': geo.get('flag', '🌐'),
                'region_city': f"{geo.get('city', '')}, {geo.get('regionName', '')}".strip(', '),
                'isp': geo.get('isp', 'Web Hosting Provider'),
                'ip': geo.get('ip', 'Unresolved'),
                'lat': geo.get('lat', 37.0902),
                'lon': geo.get('lon', -95.7129),
                'risk_level': u.get('risk_level', 'MEDIUM') if isinstance(u, dict) else 'MEDIUM'
            })
    return results


def locate_callback_phones(phone_objects):
    """Geolocates physical regions and carriers of embedded callback phone lures."""
    results = []
    if not phone_objects:
        return results

    for p in phone_objects:
        num_str = p.get('phone_number', '') if isinstance(p, dict) else str(p)
        clean_p = re.sub(r'\(WhatsApp\)', '', num_str).strip()
        loc = locate_sender(clean_p, message_type='SMS')
        if loc:
            loc['original_entry'] = num_str
            loc['risk_level'] = p.get('risk_level', 'HIGH') if isinstance(p, dict) else 'HIGH'
            results.append(loc)
    return results


def build_interactive_map_payload(sender_geo, url_geos=[], phone_geos=[]):
    """
    Constructs a unified JSON-serializable payload of geographic markers
    to render an interactive Leaflet dark-mode map on the report card.
    """
    pins = []

    # 1. Sender Pin
    if sender_geo and sender_geo.get('lat') and sender_geo.get('lon'):
        pins.append({
            'title': f"Sender Origin: {sender_geo.get('identifier')}",
            'type': 'SENDER',
            'country': sender_geo.get('country'),
            'flag': sender_geo.get('flag', '📍'),
            'location': sender_geo.get('region_city'),
            'carrier_or_isp': sender_geo.get('carrier_or_isp'),
            'lat': sender_geo.get('lat'),
            'lon': sender_geo.get('lon'),
            'color': '#38bdf8', # Sky Blue
            'icon': 'fa-paper-plane'
        })

    # 2. URL Pins
    for ug in url_geos:
        if ug.get('lat') and ug.get('lon'):
            pins.append({
                'title': f"Phishing/Web Server: {ug.get('host')}",
                'type': 'URL_HOST',
                'country': ug.get('country'),
                'flag': ug.get('flag', '🌐'),
                'location': ug.get('region_city'),
                'carrier_or_isp': ug.get('isp'),
                'lat': ug.get('lat'),
                'lon': ug.get('lon'),
                'color': '#e11d48', # Rose Red
                'icon': 'fa-server'
            })

    # 3. Callback Phone Pins
    for pg in phone_geos:
        if pg.get('lat') and pg.get('lon'):
            pins.append({
                'title': f"Callback Lure: {pg.get('identifier')}",
                'type': 'CALLBACK_PHONE',
                'country': pg.get('country'),
                'flag': pg.get('flag', '📞'),
                'location': pg.get('region_city'),
                'carrier_or_isp': pg.get('carrier_or_isp'),
                'lat': pg.get('lat'),
                'lon': pg.get('lon'),
                'color': '#f59e0b', # Amber
                'icon': 'fa-phone-volume'
            })

    return pins
