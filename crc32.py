import zlib

# Input list: (message, given_checksum)
messages_with_checksums = [
    ("I just got home, finally!", "86897c5b"),
    ("Let me know when you're on your way.", "450c770d"),
    # Continue for all message entries...
    ("Talk soon, gotta run!", "350a1682")
]

# Function to calculate CRC32 using the IEEE polynomial 0xEDB88320
def calculate_crc32_ieee(message):
    return format(zlib.crc32(message.encode()) & 0xFFFFFFFF, '08x')

# Loop through each message, calculate the checksum, and compare
for index, (message, given_checksum) in enumerate(messages_with_checksums):
    calculated_checksum = calculate_crc32_ieee(message)
    
    if calculated_checksum != given_checksum:
        print(f"Discrepancy found at index {index}:")
        print(f"Message: '{message}'")
        print(f"Given Checksum: {given_checksum}")
        print(f"Calculated Checksum: {calculated_checksum}")
