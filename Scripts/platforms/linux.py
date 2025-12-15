from ..datasets import chipset_data
from ..datasets import pci_data
from .. import cpu_identifier
from .. import gpu_identifier
from .. import utils
import subprocess
import re
import os
import glob
import time

class LinuxHardwareInfo:
    def __init__(self, rich_format=True):
        self.lookup_codename = cpu_identifier.CPUIdentifier().lookup_codename
        self.classify_gpu = gpu_identifier.GPUIdentifier().classify_gpu
        self.utils = utils.Utils(rich_format=rich_format)
        self.usb_ids = self.utils.read_file(self.utils.get_full_path("Scripts", "datasets", "usb.ids"))
        self.pci_ids = self.utils.read_file(self.utils.get_full_path("Scripts", "datasets", "pci.ids"))
        self.result = {}

    def run_command(self, command):
        """Execute shell command and return output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception as e:
            return ""

    def read_file(self, path):
        """Read file content safely"""
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except:
            return ""

    def parse_lspci_device(self, device_line):
        """Parse lspci output line to extract device information"""
        device_info = {}
        
        # Format: 00:00.0 Class: Vendor Device
        match = re.match(r'([0-9a-f:.]+)\s+(.+?):\s+(.+)', device_line, re.IGNORECASE)
        if match:
            device_info["PCI Address"] = match.group(1)
            device_info["Class"] = match.group(2)
            device_info["Name"] = match.group(3)
        
        return device_info

    def get_pci_device_id(self, pci_address):
        """Get vendor:device ID for a PCI device"""
        try:
            output = self.run_command(f"lspci -n -s {pci_address}")
            match = re.search(r'([0-9a-f]{4}):([0-9a-f]{4})', output)
            if match:
                vendor_id = match.group(1).upper()
                device_id = match.group(2).upper()
                return f"{vendor_id}-{device_id}"
        except:
            pass
        return None

    def motherboard(self):
        """Get motherboard information"""
        manufacturer = self.run_command("cat /sys/class/dmi/id/board_vendor 2>/dev/null") or "Unknown"
        model = self.run_command("cat /sys/class/dmi/id/board_name 2>/dev/null") or "Unknown"
        
        manufacturer = manufacturer.split()[0] if manufacturer != "Unknown" else manufacturer
        
        if manufacturer == model and model == "Unknown":
            system_name = "Unknown"
        else:
            system_name = " ".join(filter(lambda x: "unknown" not in x.lower(), [manufacturer, model])).upper()

        # Try to detect chipset
        chipset_model = "Unknown"
        lspci_output = self.run_command("lspci")
        
        for line in lspci_output.split('\n'):
            if 'Host bridge' in line or 'ISA bridge' in line:
                for chipset_name in chipset_data.amd_chipsets:
                    if chipset_name in line:
                        chipset_model = chipset_name
                        break
                if chipset_model == "Unknown":
                    # Try to extract chipset from line
                    match = re.search(r':\s+(.+?)(?:\s+\[|$)', line)
                    if match:
                        chipset_model = match.group(1).strip()
                break

        # Detect platform (Desktop/Laptop)
        chassis_type = self.run_command("cat /sys/class/dmi/id/chassis_type 2>/dev/null")
        platform = "Desktop"
        if chassis_type in ["8", "9", "10", "11", "14"]:  # Laptop chassis types
            platform = "Laptop"
        elif self.run_command("cat /sys/class/dmi/id/product_name 2>/dev/null | grep -i laptop"):
            platform = "Laptop"
                
        return {
            "Name": system_name,
            "Chipset": chipset_model,
            "Platform": platform
        }

    def bios(self):
        """Get BIOS/UEFI information"""
        bios_info = {}
        
        bios_info["Version"] = self.run_command("cat /sys/class/dmi/id/bios_version 2>/dev/null") or "Unknown"
        bios_date = self.run_command("cat /sys/class/dmi/id/bios_date 2>/dev/null") or "Unknown"
        
        # Try to parse and reformat date
        if bios_date != "Unknown":
            try:
                # Common formats: MM/DD/YYYY or DD/MM/YYYY
                for fmt in ["%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d"]:
                    try:
                        parsed_date = time.strptime(bios_date, fmt)
                        bios_info["Release Date"] = time.strftime("%Y-%m-%d", parsed_date)
                        break
                    except:
                        continue
                if "Release Date" not in bios_info:
                    bios_info["Release Date"] = bios_date
            except:
                bios_info["Release Date"] = bios_date
        else:
            bios_info["Release Date"] = "Unknown"
        
        # Detect system type
        machine = self.run_command("uname -m")
        if "x86_64" in machine:
            bios_info["System Type"] = "x64-based"
        elif "i386" in machine or "i686" in machine:
            bios_info["System Type"] = "x86-based"
        elif "aarch64" in machine or "arm64" in machine:
            bios_info["System Type"] = "ARM64-based"
        else:
            bios_info["System Type"] = machine or "Unknown"
        
        # Check firmware type
        if os.path.exists("/sys/firmware/efi"):
            bios_info["Firmware Type"] = "UEFI"
        else:
            bios_info["Firmware Type"] = "BIOS"
        
        # Check Secure Boot
        if bios_info["Firmware Type"] == "UEFI":
            secure_boot = self.run_command("mokutil --sb-state 2>/dev/null")
            if "enabled" in secure_boot.lower():
                bios_info["Secure Boot"] = "Enabled"
            elif "disabled" in secure_boot.lower():
                bios_info["Secure Boot"] = "Disabled"
            else:
                # Alternative method
                secure_boot_file = "/sys/firmware/efi/efivars/SecureBoot-*"
                try:
                    files = glob.glob(secure_boot_file)
                    if files:
                        with open(files[0], 'rb') as f:
                            data = f.read()
                            bios_info["Secure Boot"] = "Enabled" if data[-1] == 1 else "Disabled"
                    else:
                        bios_info["Secure Boot"] = "Unknown"
                except:
                    bios_info["Secure Boot"] = "Unknown"
        else:
            bios_info["Secure Boot"] = "N/A"

        return bios_info

    def cpu(self):
        """Get CPU information"""
        cpu_info = {}
        
        # Read /proc/cpuinfo
        cpuinfo = self.read_file("/proc/cpuinfo")
        
        cpu_brand = "Unknown"
        cpu_model = "Unknown"
        cpu_cores = 0
        cpu_count = 0
        
        for line in cpuinfo.split('\n'):
            if 'vendor_id' in line and cpu_brand == "Unknown":
                vendor = line.split(':')[-1].strip()
                if "Intel" in vendor:
                    cpu_brand = "Intel"
                elif "AMD" in vendor:
                    cpu_brand = "AMD"
                else:
                    cpu_brand = vendor
            elif 'model name' in line and cpu_model == "Unknown":
                cpu_model = line.split(':')[-1].strip()
                cpu_model = cpu_model.split("@")[0].replace(" CPU", "").strip()
            elif 'cpu cores' in line:
                try:
                    cpu_cores = int(line.split(':')[-1].strip())
                except:
                    pass
            elif line.startswith('processor'):
                cpu_count += 1
        
        # Alternative methods
        if cpu_model == "Unknown":
            cpu_model = self.run_command("lscpu | grep 'Model name' | cut -d ':' -f 2") or "Unknown"
            cpu_model = cpu_model.strip().split("@")[0].replace(" CPU", "").strip()
        
        if cpu_cores == 0:
            cores_output = self.run_command("lscpu | grep 'Core(s) per socket' | awk '{print $4}'")
            sockets_output = self.run_command("lscpu | grep 'Socket(s)' | awk '{print $2}'")
            try:
                cores_per_socket = int(cores_output) if cores_output else 1
                sockets = int(sockets_output) if sockets_output else 1
                cpu_cores = cores_per_socket * sockets
            except:
                cpu_cores = cpu_count
        
        # Get number of physical CPUs
        physical_cpus = self.run_command("lscpu | grep 'Socket(s)' | awk '{print $2}'")
        try:
            cpu_count = int(physical_cpus) if physical_cpus else 1
        except:
            cpu_count = 1
        
        # Get SIMD features
        simd_features = []
        flags = self.run_command("grep -m1 flags /proc/cpuinfo | cut -d ':' -f 2")
        
        simd_map = {
            'sse': 'SSE',
            'sse2': 'SSE2',
            'pni': 'SSE3',  # pni = Prescott New Instructions = SSE3
            'ssse3': 'SSSE3',
            'sse4_1': 'SSE4.1',
            'sse4_2': 'SSE4.2',
            'sse4a': 'SSE4a',
            'avx': 'AVX',
            'avx2': 'AVX2'
        }
        
        for flag, feature in simd_map.items():
            if flag in flags:
                simd_features.append(feature)
        
        cpu_description = cpu_model  # For codename lookup
        
        return {
            "Manufacturer": cpu_brand,
            "Processor Name": cpu_model,
            "Codename": self.lookup_codename(cpu_model, cpu_description),
            "Core Count": str(cpu_cores).zfill(2),
            "CPU Count": str(cpu_count).zfill(2),
            "SIMD Features": ", ".join(simd_features) if simd_features else "SIMD Capabilities Unknown"
        }

    def gpu(self):
        """Get GPU information"""
        gpu_info = {}
        
        # Use lspci to find VGA/3D/Display controllers
        lspci_output = self.run_command("lspci | grep -E 'VGA|3D|Display'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            # Extract PCI address
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            # Extract device name
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
                device_info.update(self.classify_gpu(device_id))
                
                # Try to get better name from pci.ids
                try:
                    vendor_id = device_id[:4]
                    dev_id = device_id[5:]
                    better_name = self.pci_ids.get(vendor_id, {}).get("devices", {}).get(dev_id)
                    if better_name:
                        device_name = better_name
                except:
                    pass
            
            # Check for Resizable BAR support (if available)
            try:
                resizeable_bar = self.run_command(f"lspci -vv -s {pci_address} | grep -i 'resizable bar'")
                if resizeable_bar:
                    device_info["Resizable BAR"] = "Supported"
            except:
                pass
            
            gpu_info[self.utils.get_unique_key(device_name, gpu_info)] = device_info
        
        return dict(sorted(gpu_info.items(), key=lambda item: item[1].get("Device Type", "")))

    def monitor(self):
        """Get monitor information"""
        monitor_info = {}
        
        # Try to get display info from xrandr
        xrandr_output = self.run_command("xrandr 2>/dev/null")
        
        if xrandr_output:
            current_monitor = None
            for line in xrandr_output.split('\n'):
                # Check for connected displays
                if ' connected' in line:
                    parts = line.split()
                    monitor_name = parts[0]
                    
                    # Determine connection type
                    connection_type = "Unknown"
                    if monitor_name.startswith('HDMI'):
                        connection_type = "HDMI"
                    elif monitor_name.startswith('DP') or monitor_name.startswith('DisplayPort'):
                        connection_type = "DP"
                    elif monitor_name.startswith('DVI'):
                        connection_type = "DVI"
                    elif monitor_name.startswith('VGA'):
                        connection_type = "VGA"
                    elif monitor_name.startswith('eDP') or monitor_name.startswith('LVDS'):
                        connection_type = "eDP"
                    
                    current_monitor = monitor_name
                    monitor_info[monitor_name] = {
                        "Connector Type": connection_type,
                        "Resolution": "Unknown"
                    }
                elif current_monitor and line.strip().startswith(tuple('0123456789')):
                    # Resolution line
                    parts = line.strip().split()
                    if parts and 'x' in parts[0]:
                        resolution = parts[0]
                        monitor_info[current_monitor]["Resolution"] = resolution
                        current_monitor = None  # Only get first resolution
        
        # Alternative: try to read EDID information
        if not monitor_info:
            edid_paths = glob.glob('/sys/class/drm/card*/card*/edid')
            for idx, edid_path in enumerate(edid_paths, 1):
                try:
                    monitor_name = f"Monitor {idx}"
                    monitor_info[monitor_name] = {
                        "Connector Type": "Unknown",
                        "Resolution": "Unknown"
                    }
                except:
                    pass
        
        return monitor_info

    def network(self):
        """Get network adapter information"""
        network_info = {}
        
        # Get network devices
        lspci_output = self.run_command("lspci | grep -E 'Network|Ethernet'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
            
            network_info[self.utils.get_unique_key(device_name, network_info)] = device_info
        
        # Also check USB network devices
        usb_net_output = self.run_command("lsusb | grep -iE 'network|ethernet|wi-fi|wireless'")
        for line in usb_net_output.split('\n'):
            if not line.strip():
                continue
            
            # Format: Bus 001 Device 001: ID 1234:5678 Device Name
            match = re.search(r'ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)', line, re.IGNORECASE)
            if match:
                vendor_id = match.group(1).upper()
                product_id = match.group(2).upper()
                device_name = match.group(3).strip()
                
                device_info = {
                    "Bus Type": "USB",
                    "Device ID": f"{vendor_id}-{product_id}"
                }
                
                network_info[self.utils.get_unique_key(device_name, network_info)] = device_info
        
        return network_info

    def sound(self):
        """Get sound devices information"""
        sound_info = {}
        
        # Get audio devices from lspci
        lspci_output = self.run_command("lspci | grep -iE 'audio|sound'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
            
            # Try to get audio endpoints (ALSA cards)
            try:
                card_num = self.run_command(f"cat /proc/asound/cards | grep -B1 '{device_name.split()[0]}' | head -1 | awk '{{print $1}}'")
                if card_num:
                    endpoints = []
                    pcm_devices = glob.glob(f'/proc/asound/card{card_num}/pcm*p/info')
                    for pcm in pcm_devices:
                        name = self.run_command(f"grep 'name:' {pcm} | cut -d ':' -f 2").strip()
                        if name:
                            endpoints.append(name)
                    if endpoints:
                        device_info["Audio Endpoints"] = endpoints
            except:
                pass
            
            sound_info[self.utils.get_unique_key(device_name, sound_info)] = device_info
        
        return sound_info

    def usb_controllers(self):
        """Get USB controller information"""
        usb_controller_info = {}
        
        lspci_output = self.run_command("lspci | grep -i 'usb controller'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
            
            usb_controller_info[self.utils.get_unique_key(device_name, usb_controller_info)] = device_info
        
        return usb_controller_info

    def input(self):
        """Get input device information"""
        input_info = {}
        
        # Get USB input devices
        lsusb_output = self.run_command("lsusb")
        
        for line in lsusb_output.split('\n'):
            if not line.strip():
                continue
            
            # Look for keyboard, mouse, touchpad, etc.
            if not re.search(r'keyboard|mouse|touchpad|trackpad|pointing', line, re.IGNORECASE):
                continue
            
            match = re.search(r'ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)', line, re.IGNORECASE)
            if match:
                vendor_id = match.group(1).upper()
                product_id = match.group(2).upper()
                device_name = match.group(3).strip()
                
                device_info = {
                    "Bus Type": "USB",
                    "Device ID": f"{vendor_id}-{product_id}"
                }
                
                # Try to get better name from usb.ids
                try:
                    better_name = self.usb_ids.get(vendor_id, {}).get("devices", {}).get(product_id)
                    if better_name:
                        device_name = better_name
                except:
                    pass
                
                input_info[self.utils.get_unique_key(device_name, input_info)] = device_info
        
        # Also check /proc/bus/input/devices for PS/2 and other devices
        try:
            devices_content = self.read_file("/proc/bus/input/devices")
            current_device = {}
            
            for line in devices_content.split('\n'):
                if line.startswith('N: Name='):
                    if current_device and 'Name' in current_device:
                        # Process previous device
                        if any(keyword in current_device.get('Name', '').lower() 
                               for keyword in ['keyboard', 'mouse', 'touchpad', 'trackpad']):
                            device_info = {"Bus Type": current_device.get('Bus', 'Unknown')}
                            input_info[self.utils.get_unique_key(current_device['Name'], input_info)] = device_info
                    
                    current_device = {'Name': line.split('Name=')[1].strip('" ')}
                elif line.startswith('H: Handlers='):
                    handlers = line.split('Handlers=')[1].strip()
                    if 'kbd' in handlers:
                        current_device['Type'] = 'Keyboard'
                    elif 'mouse' in handlers:
                        current_device['Type'] = 'Mouse'
                elif line.startswith('P: Phys='):
                    phys = line.split('Phys=')[1].strip()
                    if 'usb' in phys.lower():
                        current_device['Bus'] = 'USB'
                    elif 'isa' in phys.lower() or 'i8042' in phys.lower():
                        current_device['Bus'] = 'PS/2'
                    else:
                        current_device['Bus'] = 'Other'
            
            # Process last device
            if current_device and 'Name' in current_device:
                if any(keyword in current_device.get('Name', '').lower() 
                       for keyword in ['keyboard', 'mouse', 'touchpad', 'trackpad']):
                    device_info = {"Bus Type": current_device.get('Bus', 'Unknown')}
                    input_info[self.utils.get_unique_key(current_device['Name'], input_info)] = device_info
        except:
            pass
        
        return input_info

    def storage_controllers(self):
        """Get storage controller information"""
        storage_controller_info = {}
        
        # Get SATA, NVMe, and other storage controllers
        lspci_output = self.run_command("lspci | grep -iE 'sata|raid|storage|nvme|ahci'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
                
                # Try to get better name from pci.ids
                try:
                    vendor_id = device_id[:4]
                    dev_id = device_id[5:]
                    better_name = self.pci_ids.get(vendor_id, {}).get("devices", {}).get(dev_id)
                    if better_name:
                        device_name = better_name
                except:
                    pass
            
            # Try to find associated disk drives
            try:
                # Get block devices
                lsblk_output = self.run_command("lsblk -d -o NAME,MODEL | grep -v '^loop'")
                disk_drives = []
                for disk_line in lsblk_output.split('\n')[1:]:  # Skip header
                    if disk_line.strip():
                        parts = disk_line.split(None, 1)
                        if len(parts) >= 2:
                            disk_drives.append(parts[1].strip())
                        elif len(parts) == 1:
                            disk_drives.append(parts[0].strip())
                
                if disk_drives:
                    device_info["Disk Drives"] = disk_drives
            except:
                pass
            
            storage_controller_info[self.utils.get_unique_key(device_name, storage_controller_info)] = device_info
        
        return storage_controller_info

    def biometric(self):
        """Get biometric device information"""
        biometric_info = {}
        
        # Look for fingerprint readers and other biometric devices
        lsusb_output = self.run_command("lsusb | grep -iE 'fingerprint|biometric'")
        
        for line in lsusb_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.search(r'ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)', line, re.IGNORECASE)
            if match:
                vendor_id = match.group(1).upper()
                product_id = match.group(2).upper()
                device_name = match.group(3).strip()
                
                device_info = {
                    "Bus Type": "USB",
                    "Device ID": f"{vendor_id}-{product_id}"
                }
                
                biometric_info[self.utils.get_unique_key(device_name, biometric_info)] = device_info
        
        return biometric_info

    def bluetooth(self):
        """Get Bluetooth adapter information"""
        bluetooth_info = {}
        
        # Check USB Bluetooth adapters
        lsusb_output = self.run_command("lsusb | grep -iE 'bluetooth'")
        
        for line in lsusb_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.search(r'ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)', line, re.IGNORECASE)
            if match:
                vendor_id = match.group(1).upper()
                product_id = match.group(2).upper()
                device_name = match.group(3).strip()
                
                device_info = {
                    "Bus Type": "USB",
                    "Device ID": f"{vendor_id}-{product_id}"
                }
                
                bluetooth_info[self.utils.get_unique_key(device_name, bluetooth_info)] = device_info
        
        # Also check PCI Bluetooth devices
        lspci_output = self.run_command("lspci | grep -iE 'bluetooth'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
            
            bluetooth_info[self.utils.get_unique_key(device_name, bluetooth_info)] = device_info
        
        return bluetooth_info

    def sd_controller(self):
        """Get SD card reader information"""
        sd_controller_info = {}
        
        # Look for SD card readers
        lspci_output = self.run_command("lspci | grep -iE 'sd|mmc|card reader'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            # Skip if it's clearly not a card reader
            if 'audio' in line.lower() or 'sound' in line.lower():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
                
                # Check if it's a Realtek card reader
                if device_id in pci_data.RealtekCardReaderIDs:
                    sd_controller_info[self.utils.get_unique_key(device_name, sd_controller_info)] = device_info
                elif 'card' in device_name.lower() or 'reader' in device_name.lower():
                    sd_controller_info[self.utils.get_unique_key(device_name, sd_controller_info)] = device_info
        
        # Also check USB card readers
        lsusb_output = self.run_command("lsusb | grep -iE 'card reader|mass storage'")
        
        for line in lsusb_output.split('\n'):
            if not line.strip():
                continue
            
            if 'card' not in line.lower() and 'reader' not in line.lower():
                continue
            
            match = re.search(r'ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)', line, re.IGNORECASE)
            if match:
                vendor_id = match.group(1).upper()
                product_id = match.group(2).upper()
                device_name = match.group(3).strip()
                
                device_info = {
                    "Bus Type": "USB",
                    "Device ID": f"{vendor_id}-{product_id}"
                }
                
                sd_controller_info[self.utils.get_unique_key(device_name, sd_controller_info)] = device_info
        
        return sd_controller_info

    def system_devices(self):
        """Get system devices (chipset components, etc.)"""
        system_device_info = {}
        
        # Get ISA bridge, LPC controller, SMBus, etc.
        lspci_output = self.run_command("lspci | grep -iE 'isa bridge|lpc|smbus|host bridge'")
        
        for line in lspci_output.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'([0-9a-f:.]+)', line)
            if not match:
                continue
            
            pci_address = match.group(1)
            device_id = self.get_pci_device_id(pci_address)
            
            device_name = line.split(':', 1)[-1].strip()
            if ':' in device_name:
                device_name = device_name.split(':', 1)[-1].strip()
            
            device_info = {
                "Bus Type": "PCI",
                "PCI Address": pci_address
            }
            
            if device_id:
                device_info["Device ID"] = device_id
            
            system_device_info[self.utils.get_unique_key(device_name, system_device_info)] = device_info
        
        return system_device_info

    def hardware_collector(self):
        """Collect all hardware information"""
        self.result = {}

        steps = [
            ('Gathering motherboard information', self.motherboard, "Motherboard"),
            ('Gathering BIOS information', self.bios, "BIOS"),
            ('Gathering CPU information', self.cpu, "CPU"),
            ('Gathering GPU information', self.gpu, "GPU"),
            ('Gathering monitor information', self.monitor, "Monitor"),
            ('Gathering network information', self.network, "Network"),
            ('Gathering sound information', self.sound, "Sound"),
            ('Gathering USB controllers', self.usb_controllers, "USB Controllers"),
            ('Gathering input devices', self.input, "Input"),
            ('Gathering storage controllers', self.storage_controllers, "Storage Controllers"),
            ('Gathering biometric information', self.biometric, "Biometric"),
            ('Gathering bluetooth information', self.bluetooth, "Bluetooth"),
            ('Gathering sd controller information', self.sd_controller, "SD Controller"),
            ('Gathering system devices', self.system_devices, "System Devices")
        ]

        title = "Collecting hardware information"
        step_names = [message for message, function, attribute in steps]

        for index, (message, function, attribute) in enumerate(steps):
            self.utils.progress_bar(title, step_names, index)
            value = function()
            if not attribute:
                continue
            if value:
                self.result[attribute] = value
            else:
                print("    - No {} found.".format(attribute.lower()))

        self.utils.progress_bar(title, step_names, len(steps), done=True)

        print("Hardware information collection complete!")
        time.sleep(1)
