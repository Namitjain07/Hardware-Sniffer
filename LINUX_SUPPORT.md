# Linux Support for Hardware Sniffer

## Overview
Linux support has been successfully added to Hardware Sniffer, enabling hardware detection and reporting on Linux-based operating systems.

## Changes Made

### 1. New Linux Platform Module
**File**: `Scripts/platforms/linux.py`

A comprehensive Linux hardware detection module that mirrors the Windows implementation but uses Linux-specific system interfaces:

- **System Information Sources**:
  - `/proc/cpuinfo` - CPU information
  - `/sys/class/dmi/id/` - DMI/SMBIOS information (motherboard, BIOS)
  - `/sys/firmware/efi/` - UEFI/firmware information
  - `lspci` - PCI device enumeration
  - `lsusb` - USB device enumeration
  - `/proc/bus/input/devices` - Input device information
  - `xrandr` - Display/monitor information
  - `/proc/asound/` - Audio device information
  - `/sys/firmware/acpi/tables/` - ACPI tables

- **Hardware Detection Methods**:
  - `motherboard()` - Detects motherboard manufacturer, model, and chipset
  - `bios()` - BIOS/UEFI version, date, firmware type, Secure Boot status
  - `cpu()` - CPU manufacturer, model, codename, cores, SIMD features
  - `gpu()` - GPU detection with PCI address and device classification
  - `monitor()` - Display information via xrandr or EDID
  - `network()` - Network adapters (PCI and USB)
  - `sound()` - Audio devices with endpoint detection
  - `usb_controllers()` - USB host controllers
  - `input()` - Keyboards, mice, touchpads (USB and PS/2)
  - `storage_controllers()` - SATA, NVMe, RAID controllers with disk drives
  - `biometric()` - Fingerprint readers and other biometric devices
  - `bluetooth()` - Bluetooth adapters (PCI and USB)
  - `sd_controller()` - SD/MMC card readers
  - `system_devices()` - Chipset components (ISA bridge, LPC, SMBus, etc.)

### 2. Core Module Updates

**File**: `HardwareSniffer.py`
- Added Linux platform detection in constructor
- Imports `LinuxHardwareInfo` for Linux systems
- Updated `dump_acpi_tables()` method to support Linux:
  - Copies ACPI tables from `/sys/firmware/acpi/tables/`
  - Handles permission requirements (may need sudo)

**File**: `Hardware-Sniffer-CLI.py`
- Updated OS validation to accept both Windows and Linux
- Changed error message to reflect multi-platform support

### 3. Dependencies Update

**File**: `requirements.txt`
- Made `wmi` package Windows-specific: `wmi; sys_platform == 'win32'`
- No additional dependencies required for Linux (uses built-in system tools)

### 4. Documentation Updates

**File**: `README.md`
- Updated feature description to mention Linux support
- Changed Q&A section to indicate Linux is now supported
- Added separate "How To Use" sections for Windows and Linux
- Documented Linux-specific installation and usage instructions

## Usage on Linux

### Installation
```bash
git clone https://github.com/lzhoang2801/Hardware-Sniffer.git
cd Hardware-Sniffer
pip install -r requirements.txt
```

### Running the Tool

**Interactive Mode**:
```bash
python HardwareSniffer.py
```

**CLI Mode (Direct Export)**:
```bash
python Hardware-Sniffer-CLI.py -e
```

**Custom Output Directory**:
```bash
python Hardware-Sniffer-CLI.py -e -o /path/to/output
```

**With ACPI Dumping (requires sudo)**:
```bash
sudo python Hardware-Sniffer-CLI.py -e
```

## System Requirements

### Required Tools (usually pre-installed)
- `lspci` - PCI device listing
- `lsusb` - USB device listing
- Access to `/proc` and `/sys` filesystems

### Optional Tools
- `xrandr` - For display/monitor detection (X11 environments)
- `mokutil` - For Secure Boot status detection
- `sudo` - For ACPI table dumping

## Testing

The implementation has been tested on:
- Ubuntu/Debian-based systems
- System: ASUSTEK FX707ZC
- CPU: 12th Gen Intel Core i5-12500H

Test results show successful detection of:
- Motherboard information
- BIOS/UEFI details
- CPU specifications
- All hardware components

## Compatibility Notes

### Differences from Windows Implementation

1. **Device Location Paths**: Linux uses PCI addresses instead of Windows device paths
2. **Monitor Detection**: Uses xrandr or EDID instead of WMI
3. **ACPI Tables**: Copied from `/sys/firmware/acpi/tables/` instead of using acpidump.exe
4. **Permissions**: Some operations may require root access (especially ACPI dumping)

### Known Limitations

1. **ACPI Dumping**: Requires sudo/root permissions on Linux
2. **Monitor Detection**: Works best in X11 environments; may be limited in Wayland
3. **Secure Boot Status**: Requires `mokutil` or access to EFI variables
4. **Some Hardware Details**: May be less detailed than Windows in certain areas due to driver/interface differences

## Future Enhancements

Potential improvements for Linux support:
- Wayland display detection support
- More detailed PCI device location information
- Better integration with systemd for hardware enumeration
- Support for detecting virtualization/containerization

## Contributing

When contributing to Linux support, please ensure:
1. Code works without sudo when possible
2. Graceful fallbacks when tools are not available
3. Error handling for permission issues
4. Cross-distro compatibility (tested on multiple distributions)
