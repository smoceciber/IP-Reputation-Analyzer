import requests
import configparser
import json

config_file = "ip_analyzer.conf"
config = configparser.ConfigParser()
config.read(config_file)

abuseipdb_header = json.loads(config.get("abuseipdb", "abuseipdb_header"))

ip=""
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

    ip_country = str(data["data"].get("countryName", "N/A"))
    ip_isp = str(data["data"].get("isp", "N/A"))
    ip_domain = str(data["data"].get("domain", "N/A"))
    ip_reports = str(data["data"].get("totalReports", "N/A"))
    ip_usage = str(data["data"].get("usageType", "N/A"))
    ip_whitelisted = str(data["data"].get("isWhitelisted", "N/A"))
    ip_url = "https://www.abuseipdb.com/check/%s" % (str(ip))

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

if __name__ == "__main__":
    check_abuseipdb(ip)