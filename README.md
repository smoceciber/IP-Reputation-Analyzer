# IP-Reputation-Analyzer

The objective of the script is to facilitate the cybersecurity analyst in the process of analyzing multiple IPs on various platforms. Therefore, it makes calls to the APIs of recognized security platforms (VirusTotal, AbuseIPDB and AlienVault) to extract the information that I consider relevant for the analysis.

## Install dependencies:

pip install -r requirements.txt

## How does it work

After installing the dependencies and configuring the “ip_analyzer.conf” file with our API Keys of the indicated platforms, we must enter in the “ips.txt” file the IPs we want to analyze (one IP per line). Subsequently, we will execute the “main.py” and the “report.txt” file will be updated with the information extracted from the platforms.
