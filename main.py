import functions

# emptying report file
open('report.txt', 'w').close()

# read the ips
with open("ips.txt", "r") as file:
    ips = [line.strip() for line in file]

# for each ip in ips file, execute checkers
for ip in ips:
    functions.check_vt(ip)
    functions.check_alienvault(ip)
    functions.check_abuseipdb(ip)