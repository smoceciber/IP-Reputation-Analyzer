import functions

open('report.txt', 'w').close()

with open("ips.txt", "r") as file:
    ips = [line.strip() for line in file]

for ip in ips:
    functions.check_vt(ip)
    functions.check_alienvault(ip)
    functions.check_abuseipdb(ip)