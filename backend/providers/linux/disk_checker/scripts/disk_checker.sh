#!/bin/bash
#
# Disk Checker - A comprehensive disk information gathering script
# Compatible with most Linux distributions
#
# This script gathers:
# - Block device information
# - UUIDs
# - Disk space usage
# - LVM configuration
#

# Exit on error
set -e

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to sanitize strings for JSON
sanitize_for_json() {
    # Replace newlines, tabs, and other control characters
    echo "$1" | tr -d '\r' | tr '\n' ' ' | sed 's/"/\\"/g'
}

# Output JSON format
output_json=true

# Output file (default to stdout)
output_file="/dev/stdout"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-json)
            output_json=false
            shift
            ;;
        --output)
            output_file="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--no-json] [--output FILE]" >&2
            exit 1
            ;;
    esac
done

# Start gathering information
echo "Gathering disk information..." >&2

# Create temp files for storing results
tmp_dir=$(mktemp -d)
block_devices_file="$tmp_dir/block_devices.txt"
uuid_file="$tmp_dir/uuid.txt"
df_file="$tmp_dir/df.txt"
lvm_pv_file="$tmp_dir/lvm_pv.txt"
lvm_vg_file="$tmp_dir/lvm_vg.txt"
lvm_lv_file="$tmp_dir/lvm_lv.txt"

# Cleanup function
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

# 1. Get block device information
if command_exists lsblk; then
    # Include all device types and show more details
    lsblk -a -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,LABEL,MODEL > "$block_devices_file"
else
    echo "lsblk command not found, trying alternative methods" >&2
    # Fallback to more basic tools
    # Include more device types: SCSI, NVMe, Xen, VirtIO, MMC, IDE
    ls -la /dev/sd* /dev/nvme* /dev/xvd* /dev/vd* /dev/hd* /dev/mmcblk* /dev/md* /dev/mapper/* 2>/dev/null | awk '{print $10}' > "$block_devices_file" || true
fi

# 2. Get UUID information
if command_exists blkid; then
    blkid > "$uuid_file"
else
    echo "blkid command not found, UUID information will be limited" >&2
    ls -la /dev/disk/by-uuid/ 2>/dev/null > "$uuid_file" || true
fi

# 3. Get disk space usage
if command_exists df; then
    df -h > "$df_file"
else
    echo "df command not found, disk space information will be limited" >&2
    # No good alternative for df
    echo "No disk space information available" > "$df_file"
fi

# 4. Get LVM information if available
lvm_available=false
if command_exists pvs && command_exists vgs && command_exists lvs; then
    lvm_available=true
    pvs > "$lvm_pv_file" 2>/dev/null || echo "No physical volumes found" > "$lvm_pv_file"
    vgs > "$lvm_vg_file" 2>/dev/null || echo "No volume groups found" > "$lvm_vg_file"
    lvs > "$lvm_lv_file" 2>/dev/null || echo "No logical volumes found" > "$lvm_lv_file"
else
    echo "LVM commands not found, LVM information will not be available" >&2
    echo "LVM not available" > "$lvm_pv_file"
    echo "LVM not available" > "$lvm_vg_file"
    echo "LVM not available" > "$lvm_lv_file"
fi

# Function to extract UUID from blkid output for a device and sanitize for JSON
get_uuid() {
    local device=$1
    # Get UUIDs and join with commas if multiple, also escape any control characters
    local uuids=$(grep "$device" "$uuid_file" | grep -o 'UUID="[^"]*"' | sed 's/UUID="//;s/"//')
    sanitize_for_json "$uuids"
}

# Generate output
if [ "$output_json" = true ]; then
    # Generate JSON output
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," 
        echo "  \"hostname\": \"$(hostname)\"," 
        echo "  \"block_devices\": ["
        
        # Process block devices
        first_block=true
        while read -r line; do
            # Skip header line
            if [[ "$line" == NAME* ]]; then continue; fi
            
            # Parse line
            name=$(echo "$line" | awk '{print $1}')
            size=$(echo "$line" | awk '{print $2}')
            type=$(echo "$line" | awk '{print $3}')
            mountpoint=$(echo "$line" | awk '{print $4}')
            fstype=$(echo "$line" | awk '{print $5}')
            
            # Skip if name is empty
            if [[ -z "$name" ]]; then continue; fi
            
            # Get device path
            device="/dev/$name"
            
            # Only include actual devices and partitions
            if [[ "$type" == "disk" || "$type" == "part" ]]; then
                if [ "$first_block" = true ]; then
                    first_block=false
                else
                    echo ","
                fi
                
                uuid=$(get_uuid "$device")
                
                # Sanitize other fields for JSON
                name=$(sanitize_for_json "$name")
                device=$(sanitize_for_json "$device")
                size=$(sanitize_for_json "$size")
                type=$(sanitize_for_json "$type")
                fstype=$(sanitize_for_json "$fstype")
                mountpoint=$(sanitize_for_json "$mountpoint")
                
                echo "    {"
                echo "      \"name\": \"$name\","
                echo "      \"device\": \"$device\","
                echo "      \"size\": \"$size\","
                echo "      \"type\": \"$type\","
                if [ -n "$uuid" ]; then
                    echo "      \"uuid\": \"$uuid\","
                fi
                if [ -n "$fstype" ]; then
                    echo "      \"fstype\": \"$fstype\","
                fi
                if [ -n "$mountpoint" ]; then
                    echo "      \"mountpoint\": \"$mountpoint\","
                fi
                
                # Get usage if mounted
                if [ -n "$mountpoint" ] && [ "$mountpoint" != "none" ]; then
                    usage=$(grep "$mountpoint" "$df_file" | awk '{print $5}')
                    if [ -n "$usage" ]; then
                        usage=$(sanitize_for_json "$usage")
                        echo "      \"usage\": \"$usage\","
                    fi
                fi
                
                echo "      \"details\": {}"
                echo -n "    }"
            fi
        done < "$block_devices_file"
        echo ""
        echo "  ],"
        
        # Include LVM information if available
        if [ "$lvm_available" = true ]; then
            echo "  \"lvm\": {"
            
            # Physical volumes
            echo "    \"physical_volumes\": ["
            first_pv=true
            while read -r line; do
                # Skip header or empty lines
                if [[ "$line" == PV* || -z "$line" || "$line" == "No physical volumes found" ]]; then continue; fi
                
                if [ "$first_pv" = true ]; then
                    first_pv=false
                else
                    echo ","
                fi
                
                pv_name=$(echo "$line" | awk '{print $1}')
                vg_name=$(echo "$line" | awk '{print $2}')
                pv_size=$(echo "$line" | awk '{print $5}')
                
                # Sanitize fields
                pv_name=$(sanitize_for_json "$pv_name")
                vg_name=$(sanitize_for_json "$vg_name")
                pv_size=$(sanitize_for_json "$pv_size")
                
                echo "      {"
                echo "        \"name\": \"$pv_name\","
                echo "        \"vg\": \"$vg_name\","
                echo "        \"size\": \"$pv_size\""
                echo -n "      }"
            done < "$lvm_pv_file"
            echo ""
            echo "    ],"
            
            # Volume groups
            echo "    \"volume_groups\": ["
            first_vg=true
            while read -r line; do
                # Skip header or empty lines
                if [[ "$line" == VG* || -z "$line" || "$line" == "No volume groups found" ]]; then continue; fi
                
                if [ "$first_vg" = true ]; then
                    first_vg=false
                else
                    echo ","
                fi
                
                vg_name=$(echo "$line" | awk '{print $1}')
                vg_size=$(echo "$line" | awk '{print $6}')
                
                # Sanitize fields
                vg_name=$(sanitize_for_json "$vg_name")
                vg_size=$(sanitize_for_json "$vg_size")
                
                echo "      {"
                echo "        \"name\": \"$vg_name\","
                echo "        \"size\": \"$vg_size\""
                echo -n "      }"
            done < "$lvm_vg_file"
            echo ""
            echo "    ],"
            
            # Logical volumes
            echo "    \"logical_volumes\": ["
            first_lv=true
            while read -r line; do
                # Skip header or empty lines
                if [[ "$line" == LV* || -z "$line" || "$line" == "No logical volumes found" ]]; then continue; fi
                
                if [ "$first_lv" = true ]; then
                    first_lv=false
                else
                    echo ","
                fi
                
                lv_name=$(echo "$line" | awk '{print $1}')
                vg_name=$(echo "$line" | awk '{print $2}')
                lv_size=$(echo "$line" | awk '{print $4}')
                
                # Sanitize fields
                lv_name=$(sanitize_for_json "$lv_name")
                vg_name=$(sanitize_for_json "$vg_name")
                lv_size=$(sanitize_for_json "$lv_size")
                
                echo "      {"
                echo "        \"name\": \"$lv_name\","
                echo "        \"vg\": \"$vg_name\","
                echo "        \"size\": \"$lv_size\","
                
                # Find mount point for this LV
                lv_path="/dev/$vg_name/$lv_name"
                lv_mount=$(grep "$lv_path" "$df_file" | awk '{print $6}')
                if [ -n "$lv_mount" ]; then
                    lv_mount=$(sanitize_for_json "$lv_mount")
                    echo "        \"mountpoint\": \"$lv_mount\","
                    
                    # Get usage if mounted
                    usage=$(grep "$lv_mount" "$df_file" | awk '{print $5}')
                    if [ -n "$usage" ]; then
                        usage=$(sanitize_for_json "$usage")
                        echo "        \"usage\": \"$usage\","
                    fi
                fi
                
                lv_path=$(sanitize_for_json "$lv_path")
                echo "        \"device\": \"$lv_path\""
                echo -n "      }"
            done < "$lvm_lv_file"
            echo ""
            echo "    ]"
            echo "  }"
        else
            echo "  \"lvm\": {}"
        fi
        
        echo "}"
    } > "$output_file"
else
    # Generate human-readable output
    {
        echo "===== Disk Information Report ====="
        echo "Hostname: $(hostname)"
        echo "Date: $(date)"
        echo ""
        
        echo "===== Block Devices ====="
        cat "$block_devices_file"
        echo ""
        
        echo "===== Disk Space Usage ====="
        cat "$df_file"
        echo ""
        
        echo "===== UUID Information ====="
        cat "$uuid_file"
        echo ""
        
        if [ "$lvm_available" = true ]; then
            echo "===== LVM Physical Volumes ====="
            cat "$lvm_pv_file"
            echo ""
            
            echo "===== LVM Volume Groups ====="
            cat "$lvm_vg_file"
            echo ""
            
            echo "===== LVM Logical Volumes ====="
            cat "$lvm_lv_file"
        else
            echo "===== LVM Information ====="
            echo "LVM not available on this system"
        fi
    } > "$output_file"
fi

# Print completion message unless outputting to stdout
if [ "$output_file" != "/dev/stdout" ]; then
    echo "Disk information saved to $output_file" >&2
fi

exit 0
