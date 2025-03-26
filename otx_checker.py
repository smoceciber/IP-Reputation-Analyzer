from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from datetime import datetime
import configparser

config_file = "ip_analyzer.conf"
config = configparser.ConfigParser()
config.read(config_file)

otx_key = config.get("otx", "key")

otx = OTXv2(otx_key)

ip=""
def check_alienvault(ip):
    data = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
    no_pulses = len(data["general"]["pulse_info"]["pulses"])
    i = 0 
    with open("report.txt", "a") as report:
        if no_pulses == 0:
            report.write("\nNo pulses found for IP " + ip + "\n")
            
        else:
            report.write("\nAlienVault pulses for IP %s\n" % (str(ip)))
            while i < no_pulses:
                created = (str(data["general"]["pulse_info"]["pulses"][i]["created"]))
                created_obj = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%f")
                pulse_date = created_obj.strftime("%d-%m-%Y %H:%M:%S")
                pulse_name = str(data["general"]["pulse_info"]["pulses"][i]["name"])

                report.write("Pulse: %s\n" % (str(pulse_name)))
                report.write("Created on: %s\n" % (str(pulse_date)))
                i += 1

    return None

if __name__ == "__main__":
    check_alienvault(ip)