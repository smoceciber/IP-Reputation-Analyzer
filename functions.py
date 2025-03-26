import requests
import configparser
import json
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from datetime import datetime

# config file definition
config_file = "ip_analyzer.conf"
config = configparser.ConfigParser()
config.read(config_file)

# variable definition
vt_header = json.loads(config.get("vt", "vt_header"))
abuseipdb_header = json.loads(config.get("abuseipdb", "abuseipdb_header"))
otx_key = config.get("otx", "key")
otx = OTXv2(otx_key)

ip=""

def check_vt(ip):
    r = requests.get(
        url="https://www.virustotal.com/api/v3/ip_addresses/%s" % (str(ip)),
        headers=vt_header,
    )
    data = r.json()

    # parsing data from json to variables
    ip_owner = str(data["data"]["attributes"].get("as_owner", "N/A"))
    ip_asn = str(data["data"]["attributes"].get("asn", "N/A"))
    ip_network = str(data["data"]["attributes"].get("network", "N/A"))
    ip_geolocalization = str(data["data"]["attributes"].get("country", "N/A"))
    ip_last_analysis_stats = str(
        data["data"]["attributes"].get("last_analysis_stats", "N/A")
    )
    ip_reputation = str(data["data"]["attributes"].get("reputation", "N/A"))
    ip_url = "https://www.virustotal.com/gui/ip-address/%s" % (str(ip))

    # writing variables to report
    with open("report.txt", "a") as report:
        report.write("\nVirusTotal analysis for IP %s\n" % (str(ip)))
        report.write("IP Owner: %s\n" % (str(ip_owner)))
        report.write("ASN: %s\n" % (str(ip_asn)))
        report.write("IP Network: %s\n" % (str(ip_network)))
        report.write("Geolocalization: %s\n" % (str(ip_geolocalization)))
        report.write("VirusTotal analysis: %s\n" % (str(ip_last_analysis_stats)))
        report.write("Reputation: %s\n" % (str(ip_reputation)))
        report.write("%s\n" % (str(ip_url)))
    return None

def check_abuseipdb(ip):
    r = requests.get(
    url="https://api.abuseipdb.com/api/v2/check",
    params={
        "ipAddress": "%s" % (str(ip)), 
        "maxAgeInDays": 90,
        "verbose": "true"
    },
    headers=abuseipdb_header
)
    data = r.json()

    # parsing data from json to variables
    ip_country = str(data["data"].get("countryName", "N/A"))
    ip_isp = str(data["data"].get("isp", "N/A"))
    ip_domain = str(data["data"].get("domain", "N/A"))
    ip_reports = str(data["data"].get("totalReports", "N/A"))
    ip_usage = str(data["data"].get("usageType", "N/A"))
    ip_whitelisted = str(data["data"].get("isWhitelisted", "N/A"))
    ip_url = "https://www.abuseipdb.com/check/%s" % (str(ip))

    # writing variables to report
    with open("report.txt", "a") as report:
        report.write("\nAbuseIPDB analysis for IP %s\n" % (str(ip)))
        report.write("IP Owner: %s\n" % (str(ip_isp)))
        report.write("IP Domain: %s\n" % (str(ip_domain)))
        report.write("IP Country: %s\n" % (str(ip_country)))
        report.write("IP Usage Type: %s\n" % (str(ip_usage)))
        report.write("Is Whitelisted: %s\n" % (str(ip_whitelisted)))
        report.write("Number of Reports: %s\n" % (str(ip_reports)))
        report.write("%s\n" % (str(ip_url)))

    return None

def check_alienvault(ip):
    data = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
    
    # get the number of pulses
    no_pulses = len(data["general"]["pulse_info"]["pulses"])
    # pulse counter
    i = 0 

    with open("report.txt", "a") as report:
        # check if the ip has pulses
        if no_pulses == 0:
            report.write("\nNo pulses found for IP " + ip + "\n")
        else:
            report.write("\nAlienVault pulses for IP %s\n" % (str(ip)))
            while i < no_pulses:
                # parsing data from json to variables
                created = (str(data["general"]["pulse_info"]["pulses"][i]["created"]))
                # creating a human readable date
                created_obj = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%f")
                pulse_date = created_obj.strftime("%d-%m-%Y %H:%M:%S")
                pulse_name = str(data["general"]["pulse_info"]["pulses"][i]["name"])
                # writing variables to report
                report.write("Pulse: %s\n" % (str(pulse_name)))
                report.write("Created on: %s\n" % (str(pulse_date)))
                i += 1

    return None