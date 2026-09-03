from app.osint import check_safe_browsing

print("=== Known-bad test URL (should flag) ===")
result = check_safe_browsing("https://testsafebrowsing.appspot.com/s/malware.html")
print(result)

print("\n=== Known-clean URL (should NOT flag) ===")
result = check_safe_browsing("https://www.google.com")
print(result)