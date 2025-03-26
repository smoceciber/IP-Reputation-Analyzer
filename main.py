import vt_checker, otx_checker, abuseipdb_checker

open('report.txt', 'w').close()

with open("ips.txt", "r") as file:
    ips = [line.strip() for line in file]

for ip in ips:
    vt_checker.check_vt(ip)
    otx_checker.check_alienvault(ip)
    abuseipdb_checker.check_abuseipdb(ip)