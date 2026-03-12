
import os
import subprocess
import sys

# Define the root directory for pcap files
pcap_root_dir = 'captures_IoT-Sentinel'

# Define the output CSV file
output_csv = 'all_data.csv'

# Define the absolute path to tshark
# On macOS, this is the default location.
tshark_path = '/Applications/Wireshark.app/Contents/MacOS/tshark'

# Check if tshark exists at the specified path
if not os.path.exists(tshark_path):
    print(f"Error: tshark not found at {tshark_path}")
    print("Please ensure Wireshark is installed in the default location, or update the tshark_path in this script.")
    sys.exit(1)

# Define the fields to extract, matching the notebook
fields = [
    'frame.time',
    'ip.src',
    'ip.dst',
    '_ws.col.Protocol',
    'tcp.srcport',
    'tcp.dstport',
    'udp.srcport',
    'udp.dstport',
    'frame.len'
]

# Build the -e arguments for tshark
tshark_fields_args = [arg for field in fields for arg in ['-e', field]]

# Find all pcap files
pcap_files = []
for root, dirs, files in os.walk(pcap_root_dir):
    for file in files:
        if file.endswith('.pcap'):
            pcap_files.append(os.path.join(root, file))

# Check if pcap files were found
if not pcap_files:
    print(f"No .pcap files found in '{pcap_root_dir}'. Please check the directory.")
    sys.exit(0)

print(f"Found {len(pcap_files)} pcap files. Starting processing...")

# Process the first file to create the CSV with a header
try:
    first_file = pcap_files.pop(0)
    print(f"Processing (1/{len(pcap_files) + 1}): {first_file}")
    command = [
        tshark_path,
        '-r', first_file,
        '-T', 'fields'
    ] + tshark_fields_args + [
        '-E', 'header=y',
        '-E', 'separator=,',
        '-E', 'quote=d'  # Force quoting of all fields
    ]
    
    with open(output_csv, 'w') as f_out:
        subprocess.run(command, stdout=f_out, check=True, stderr=subprocess.PIPE)

    # Process the remaining files and append to the CSV without a header
    for i, pcap_file in enumerate(pcap_files):
        print(f"Processing ({i + 2}/{len(pcap_files) + 1}): {pcap_file}")
        command = [
            tshark_path,
            '-r', pcap_file,
            '-T', 'fields'
        ] + tshark_fields_args + [
            '-E', 'header=n',
            '-E', 'separator=,',
            '-E', 'quote=d'  # Force quoting of all fields
        ]
        with open(output_csv, 'a') as f_out:
            subprocess.run(command, stdout=f_out, check=True, stderr=subprocess.PIPE)

    print("\nProcessing complete!")
    print(f"All data has been extracted and saved to '{output_csv}'.")

except subprocess.CalledProcessError as e:
    print("\nAn error occurred while running tshark.")
    print(f"Command: {' '.join(e.cmd)}")
    print(f"Error message: {e.stderr.decode('utf-8')}")
except Exception as e:
    print(f"\nAn unexpected error occurred: {e}")
