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
    'frame.number',
    'frame.time',
    'frame.time_epoch',
    'frame.time_delta',
    'frame.time_delta_displayed',
    'eth.src',
    'eth.dst',
    'ip.src',
    'ip.dst',
    'ip.proto',
    'ip.ttl',
    '_ws.col.Protocol',
    'tcp.srcport',
    'tcp.dstport',
    'tcp.stream',
    'tcp.seq',
    'tcp.ack',
    'tcp.window_size_value',
    'tcp.len',
    'tcp.flags',
    'tcp.flags.syn',
    'tcp.flags.ack',
    'tcp.flags.fin',
    'tcp.flags.reset',
    'tcp.flags.push',
    'tcp.flags.urg',
    'udp.srcport',
    'udp.dstport',
    'udp.length',
    'data.len',
    'frame.len'
]

# Build the -e arguments for tshark
tshark_fields_args = [arg for field in fields for arg in ['-e', field]]


def get_device_label(pcap_file_path):
    relative_path = os.path.relpath(pcap_file_path, pcap_root_dir)
    path_parts = relative_path.split(os.sep)
    if len(path_parts) > 1:
        return path_parts[0]
    return os.path.splitext(os.path.basename(pcap_file_path))[0]

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

# Process all files and write a single CSV with device labels
try:
    with open(output_csv, 'w') as f_out:
        header_row = ['"device_label"'] + [f'"{field}"' for field in fields]
        f_out.write(','.join(header_row) + '\n')

        for i, pcap_file in enumerate(pcap_files):
            print(f"Processing ({i + 1}/{len(pcap_files)}): {pcap_file}")
            device_label = get_device_label(pcap_file)
            command = [
                tshark_path,
                '-r', pcap_file,
                '-T', 'fields'
            ] + tshark_fields_args + [
                '-E', 'header=n',
                '-E', 'separator=,',
                '-E', 'quote=d'
            ]

            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True
            )

            for row in result.stdout.splitlines():
                if row.strip():
                    f_out.write(f'"{device_label}",{row}\n')

    print("\nProcessing complete!")
    print(f"All data has been extracted and saved to '{output_csv}'.")

except subprocess.CalledProcessError as e:
    print("\nAn error occurred while running tshark.")
    print(f"Command: {' '.join(e.cmd)}")
    print(f"Error message: {e.stderr}")
except Exception as e:
    print(f"\nAn unexpected error occurred: {e}")
