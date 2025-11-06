#!/usr/bin/env python3
"""
Comprehensive Bluetooth scanning test for Ragnar
Tests the complete Bluetooth discovery workflow with real devices
"""

import requests
import json
import time
import sys

def comprehensive_bluetooth_test():
    """Test comprehensive Bluetooth scanning workflow"""
    base_url = "http://localhost:8000"
    
    print("🔵 Comprehensive Bluetooth Scanning Test")
    print("=" * 60)
    
    # Test 1: Basic connectivity
    print("📋 Phase 1: Server Connectivity")
    print("-" * 30)
    try:
        response = requests.get(f"{base_url}/api/bluetooth/status", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running and accessible")
        else:
            print("❌ Server responded with error")
            return
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Please start: python webapp_modern.py")
        return
    
    # Test 2: Complete scan workflow
    print("\n🔍 Phase 2: Complete Scan Workflow")
    print("-" * 40)
    
    try:
        # Step 1: Check initial status
        print("Step 1: Checking Bluetooth status...")
        response = requests.get(f"{base_url}/api/bluetooth/status")
        status = response.json()
        print(f"   Initial status: {'Enabled' if status.get('enabled') else 'Disabled'}")
        
        # Step 2: Enable Bluetooth
        print("Step 2: Enabling Bluetooth...")
        response = requests.post(f"{base_url}/api/bluetooth/enable")
        if response.status_code == 200:
            print("   ✅ Bluetooth enabled")
            time.sleep(2)  # Wait for Bluetooth to stabilize
        else:
            print("   ❌ Failed to enable Bluetooth")
            return
        
        # Step 3: Start discovery scan
        print("Step 3: Starting device discovery...")
        response = requests.post(f"{base_url}/api/bluetooth/scan/start")
        if response.status_code == 200:
            print("   ✅ Discovery started")
        else:
            print("   ❌ Failed to start discovery")
            return
        
        # Step 4: Wait for devices to be discovered
        print("Step 4: Scanning for devices (10 seconds)...")
        for i in range(10, 0, -1):
            print(f"   Scanning... {i} seconds remaining", end='\r')
            time.sleep(1)
        print("   Scan period completed" + " " * 20)
        
        # Step 5: Get discovered devices
        print("Step 5: Retrieving discovered devices...")
        response = requests.get(f"{base_url}/api/bluetooth/devices")
        if response.status_code == 200:
            result = response.json()
            devices = result.get('devices', [])
            print(f"   ✅ Found {len(devices)} device(s)")
            
            if devices:
                print("\n📱 Discovered Devices:")
                print("-" * 50)
                for i, device in enumerate(devices, 1):
                    name = device.get('name', 'Unknown Device')
                    address = device.get('address', 'Unknown')
                    rssi = device.get('rssi', 'N/A')
                    device_class = device.get('device_class', 'Unknown')
                    paired = device.get('paired', False)
                    services = device.get('services', [])
                    
                    print(f"Device {i}:")
                    print(f"   Name: {name}")
                    print(f"   Address: {address}")
                    print(f"   Signal Strength (RSSI): {rssi}")
                    print(f"   Device Class: {device_class}")
                    print(f"   Paired: {'Yes' if paired else 'No'}")
                    if services:
                        print(f"   Services: {len(services)} available")
                    print()
            else:
                print("   No devices discovered during scan period")
        else:
            print("   ❌ Failed to retrieve devices")
        
        # Step 6: Test discoverable mode
        print("Step 6: Testing discoverable mode...")
        response = requests.post(f"{base_url}/api/bluetooth/discoverable/on")
        if response.status_code == 200:
            print("   ✅ Device is now discoverable")
            time.sleep(2)
            
            response = requests.post(f"{base_url}/api/bluetooth/discoverable/off")
            if response.status_code == 200:
                print("   ✅ Device is now hidden")
            else:
                print("   ⚠️ Could not hide device")
        else:
            print("   ⚠️ Could not make device discoverable")
        
        # Step 7: Stop scanning (with improved error handling)
        print("Step 7: Stopping device discovery...")
        response = requests.post(f"{base_url}/api/bluetooth/scan/stop")
        if response.status_code == 200:
            print("   ✅ Discovery stopped")
        else:
            print("   ⚠️ Discovery stop reported error (might still work)")
            error_data = response.json()
            print(f"   Error: {error_data.get('error', 'Unknown error')}")
        
        # Step 8: Cleanup - disable Bluetooth
        print("Step 8: Disabling Bluetooth...")
        response = requests.post(f"{base_url}/api/bluetooth/disable")
        if response.status_code == 200:
            print("   ✅ Bluetooth disabled")
        else:
            print("   ⚠️ Could not disable Bluetooth")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return
    
    print("\n" + "=" * 60)
    print("🎉 Comprehensive Bluetooth test completed!")
    print("\n💡 Summary:")
    print("- Ragnar's Bluetooth scanning uses 'bluetoothctl' commands")
    print("- Discovery finds nearby Bluetooth devices")
    print("- Device information includes name, address, signal strength")
    print("- The system can make your device discoverable to others")
    print("- All operations are accessible via REST API endpoints")

def manual_scan_guide():
    """Show manual bluetoothctl commands for reference"""
    print("\n🔧 Manual Bluetooth Commands Reference")
    print("=" * 45)
    print("If you want to scan manually using bluetoothctl:")
    print()
    print("1. bluetoothctl                    # Enter interactive mode")
    print("2. power on                       # Enable Bluetooth")
    print("3. scan on                        # Start discovery")
    print("4. devices                        # List found devices")
    print("5. info <MAC_ADDRESS>             # Get device details")
    print("6. scan off                       # Stop discovery")
    print("7. quit                           # Exit bluetoothctl")
    print()
    print("Example for your discovered devices:")
    print("bluetoothctl info 44:C6:5D:6B:BC:DC")
    print("bluetoothctl info 51:F5:34:6A:BA:23")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--manual":
        manual_scan_guide()
    else:
        comprehensive_bluetooth_test()
        manual_scan_guide()