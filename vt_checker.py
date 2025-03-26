import requests
import configparser
import json

config_file = "ip_analyzer.conf"
config = configparser.ConfigParser()
config.read(config_file)

vt_header = json.loads(config.get("vt", "vt_header"))

ip=""
def check_vt(ip):
    r = requests.get(
        url="https://www.virustotal.com/api/v3/ip_addresses/%s" % (str(ip)),
        headers=vt_header,
    )
    data = r.json()

    ip_owner = str(data["data"]["attributes"].get("as_owner", "N/A"))
    ip_asn = str(data["data"]["attributes"].get("asn", "N/A"))
    ip_network = str(data["data"]["attributes"].get("network", "N/A"))
    ip_geolocalization = str(data["data"]["attributes"].get("country", "N/A"))
    ip_last_analysis_stats = str(
        data["data"]["attributes"].get("last_analysis_stats", "N/A")
    )
    ip_reputation = str(data["data"]["attributes"].get("reputation", "N/A"))
    ip_url = "https://www.virustotal.com/gui/ip-address/%s" % (str(ip))


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

if __name__ == "__main__":
    check_vt(ip)