from app.osint import check_safe_browsing
from app.osint import check_virustotal

print("=== Known-bad test URL (should flag) ===")
result = check_safe_browsing("https://testsafebrowsing.appspot.com/s/malware.html")
print(result)

print("\n=== Known-clean URL (should NOT flag) ===")
result = check_safe_browsing("https://www.google.com")
print(result)


print("\n=== VirusTotal: known-clean URL ===")
result = check_virustotal("https://www.google.com")
print(result)

print("\n=== VirusTotal: EICAR test URL (should flag) ===")
result = check_virustotal("https://secure.eicar.org/eicar.com")
print(result)