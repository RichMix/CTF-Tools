import pyshark

# Load your .pcap file
pcap_file = '"C:\Users\richi\OneDrive\Desktop\ncl_fall\home-2024-fall.pcap"'

# Initialize the capture
capture = pyshark.FileCapture(pcap_file)

# Display a summary of the first 10 packets
for i, packet in enumerate(capture[:10]):
    print(f"Packet {i + 1}:")
    print(f"  Time: {packet.sniff_time}")
    print(f"  Source IP: {packet.ip.src if hasattr(packet, 'ip') else 'N/A'}")
    print(f"  Destination IP: {packet.ip.dst if hasattr(packet, 'ip') else 'N/A'}")
    print(f"  Protocol: {packet.highest_layer}")
    print(f"  Info: {packet.info if hasattr(packet, 'info') else 'No info'}\n")

# Close the capture after processing
capture.close()
