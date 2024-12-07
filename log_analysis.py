import re
from collections import Counter
import csv
import matplotlib.pyplot as plt

# Configuration
log_file = "log_data.txt"  # Replace with your actual log file path
threshold = 10  # Threshold for suspicious activity detection
output_csv = "log_analysis_results.csv"

# Parsing functions
def parse_log_file(file_path):
    ip_addresses = []
    endpoints = []
    failed_logins = []

    with open(file_path, "r") as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip_addresses.append(ip_match.group(1))

            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST) (/[^ ]*)', line)
            if endpoint_match:
                endpoints.append(endpoint_match.group(1))

            # Detect failed logins
            failed_login_match = re.match(r"^(\d+\.\d+\.\d+\.\d+).*\"POST /login HTTP/1.1\" 401", line)
            if failed_login_match:
                failed_logins.append(failed_login_match.group(1))

    return ip_addresses, endpoints, failed_logins

# Analysis functions
def analyze_data(ip_addresses, endpoints, failed_logins):
    # Count requests per IP
    ip_count = Counter(ip_addresses)

    # Count endpoint accesses
    endpoint_count = Counter(endpoints)

    # Identify suspicious activity
    failed_login_count = Counter(failed_logins)
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > threshold}

    return ip_count, endpoint_count, suspicious_ips

# Save results to CSV
def save_to_csv(ip_count, endpoint_count, suspicious_ips, output_file):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_count.items())

        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        most_accessed = endpoint_count.most_common(1)[0]
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())

# Generate visualizations
def generate_visualizations(ip_count, endpoint_count):
    # Visualization: Requests per IP
    ip_addresses, ip_counts = zip(*ip_count.most_common())
    plt.figure(figsize=(10, 6))
    plt.bar(ip_addresses, ip_counts, color="skyblue")
    plt.title("Requests per IP Address", fontsize=16)
    plt.xlabel("IP Address", fontsize=12)
    plt.ylabel("Request Count", fontsize=12)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("requests_per_ip.png")
    plt.show()

    # Visualization: Endpoint Access Frequency
    endpoints, endpoint_counts = zip(*endpoint_count.most_common())
    plt.figure(figsize=(10, 6))
    plt.bar(endpoints, endpoint_counts, color="lightgreen")
    plt.title("Endpoint Access Frequency", fontsize=16)
    plt.xlabel("Endpoint", fontsize=12)
    plt.ylabel("Access Count", fontsize=12)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("endpoint_access_frequency.png")
    plt.show()

# Main script
if __name__ == "__main__":
    # Parse the log file
    ip_addresses, endpoints, failed_logins = parse_log_file(log_file)

    # Analyze the data
    ip_count, endpoint_count, suspicious_ips = analyze_data(ip_addresses, endpoints, failed_logins)

    # Display results
    print("IP Address Request Count:")
    for ip, count in ip_count.most_common():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = endpoint_count.most_common(1)[0]
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_count, endpoint_count, suspicious_ips, output_csv)
    print(f"\nResults saved to {output_csv}")

    # Generate visualizations
    generate_visualizations(ip_count, endpoint_count)
