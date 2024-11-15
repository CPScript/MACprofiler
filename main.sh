import sys
import subprocess
import nmap
from mac_vendor_lookup import MacLookup, MacNotFoundError

def check_dependencies():
    required_modules = ["python-nmap", "mac-vendor-lookup"]
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module.split('-')[0])
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        print("The following required modules are missing:")
        for module in missing_modules:
            print(f"- {module}")
        print("\nTo install them, run:")
        print(f"pip install {' '.join(missing_modules)}")
        sys.exit(1)

def classify_device(mac):
    """Classify a device based on its MAC vendor."""
    try:
        vendor = MacLookup().lookup(mac)
        vendor_lower = vendor.lower()
        if "camera" in vendor_lower:
            return "Camera"
        elif "router" in vendor_lower or "network" in vendor_lower:
            return "Router"
        elif "phone" in vendor_lower or "mobile" in vendor_lower:
            return "Phone"
        elif "pc" in vendor_lower or "computer" in vendor_lower or "laptop" in vendor_lower:
            return "Computer"
        else:
            return f"Unknown device (Vendor: {vendor})"
    except MacNotFoundError:
        return "Unknown vendor/device"

def scan_network(network_range):
    """Perform an Nmap scan and analyze results."""
    scanner = nmap.PortScanner()
    print(f"Scanning the network: {network_range}...")

    try:
        scanner.scan(hosts=network_range, arguments="-sn")  # Ping scan
        devices = []

        for host in scanner.all_hosts():
            mac = scanner[host]["addresses"].get("mac", "N/A")
            if mac != "N/A":
                device_type = classify_device(mac)
                devices.append((host, mac, device_type))
        
        return devices
    except Exception as e:
        print(f"Error during scan: {e}")
        return []

def main():
    print("Nmap MAC Scanner")
    network_range = input("Enter the network range (e.g., 192.168.1.0/24): ").strip()
    devices = scan_network(network_range)

    if devices:
        print("\nDiscovered devices:")
        for ip, mac, device_type in devices:
            print(f"IP: {ip} | MAC: {mac} | Device Type: {device_type}")
    else:
        print("No devices found or an error occurred.")

if __name__ == "__main__":
    MacLookup().update_vendors()
    main()
