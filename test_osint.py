from app.osint import check_safe_browsing
from app.osint import check_virustotal
from app.osint import check_urlscan
# from app.osint import check_named_entity
from app.osint import check_named_entity
from app.osint import run_osint_checks
import time



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


print("\n=== urlscan.io: well-known domain (should have history) ===")
result = check_urlscan("https://www.google.com")
print(result)

print("\n=== urlscan.io: made-up domain (should be new/unseen) ===")
result = check_urlscan("https://xk7q9z-totally-fake-domain-test.com")
print(result)


print("\n=== Tavily: known scam-adjacent phrase ===")
result = check_named_entity("IRS tax refund scam")
print(result)

print("\n=== Tavily: real institution, should not read as scam ===")
result = check_named_entity("Taylor's University IIMS College")
print(result)


print("\n=== Combined OSINT check (concurrent) ===")
start = time.time()
result = run_osint_checks(
    url="https://www.google.com",
    named_entities=["IRS tax refund scam"],
)
elapsed = time.time() - start
print(f"Completed in {elapsed:.2f}s")
print(result)