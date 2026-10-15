import re
from collections import Counter

# Step 1: Read the SSH log file...............................................
with open("OpenSSH_2k.log", "r") as file:
    logs = file.readlines()

# Step 2: Create a dictionary to count failed attempts........................
failed_ips = Counter()

# Step 3: Check each log......................................................
for log in logs:

    if "Failed password" in log:

        # Extract source IP address...........................................
        match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)

        if match:
            ip = match.group(1)
            failed_ips[ip] += 1

# Step 4: Detection rule.......................................................
print("SSH Brute Force Detection Results")
print("---------------------------------")

alert_found = False

for ip, count in failed_ips.items():

    if count >= 5:
        print(f"ALERT: {ip} has {count} failed login attempts")
        alert_found = True

if not alert_found:
    print("No suspicious IP addresses detected")
