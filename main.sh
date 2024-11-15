import sys
import subprocess
from nmap import PortScanner
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
        print("\nThe following required modules are missing:")
        for module in missing_modules:
            print(f"- {module}")
        print("\nTo install them, run:")
        print(f"pip install {' '.join(missing_modules)}")
        sys.exit(1)

def classify_device(mac):
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
    except Exception as e:
        return f"Error classifying device: {e}"

def scan_network(network_range):
    scanner = PortScanner()
    print(f"\nScanning the network: {network_range}...")

    try:
        scanner.scan(hosts=network_range, arguments="-sn")
        devices = []

        for host in scanner.all_hosts():
            mac = scanner[host]["addresses"].get("mac", "N/A")
            if mac != "N/A":
                device_type = classify_device(mac)
                devices.append((host, mac, device_type))
        
        return devices
    except Exception as e:
        print(f"\nError during scan: {e}")
        return []

def display_devices(devices):
    print("\nDiscovered devices:")
    if devices:
        for ip, mac, device_type in devices:
            print(f"IP: {ip} | MAC: {mac} | Device Type: {device_type}")
    else:
        print("No devices found.")

def main():
    print("Nmap MAC Scanner")
    try:
        print("Updating MAC vendor database...")
        MacLookup().update_vendors()

        network_range = input("\nEnter the network range (e.g., 192.168.1.0/24): ").strip()
        if not network_range:
            raise ValueError("Network range cannot be empty.")

        devices = scan_network(network_range)
        display_devices(devices)

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
    except ValueError as ve:
        print(f"\nInput error: {ve}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        print("\nProgram terminated.")

if __name__ == "__main__":
    check_dependencies()
    main()
