def read_file_hex(file_path):
    """
    Reads a file and returns its content as a hexadecimal string.
    """
    try:
        with open(file_path, 'rb') as file:
            return file.read().hex()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        return None


def extract_udp_packets(hex_data):
    """
    Extracts UDP packets from hexadecimal data.
    Assumes the data contains raw network traffic.
    """
    udp_packets = []
    step = 2  # Each byte is represented by 2 hex characters
    i = 0

    while i + 16 <= len(hex_data):  # Minimum UDP header size is 8 bytes (16 hex characters)
        # Extract potential UDP header
        src_port = int(hex_data[i:i + 4], 16)       # First 2 bytes: Source Port
        dst_port = int(hex_data[i + 4:i + 8], 16)  # Next 2 bytes: Destination Port
        length = int(hex_data[i + 8:i + 12], 16)   # Next 2 bytes: Length
        checksum = hex_data[i + 12:i + 16]         # Next 2 bytes: Checksum

        # Validate UDP packet (basic check: length field matches actual data)
        if length * 2 <= len(hex_data[i:]):
            udp_packet = hex_data[i:i + length * 2]
            udp_packets.append(udp_packet)
            i += length * 2  # Move to the next potential packet
        else:
            i += step  # Move forward by one byte if no valid packet is found

    return udp_packets


# Main Execution
if __name__ == "__main__":
    # Path to the input file containing raw network traffic
    input_file_path = "extracted_udp_packets.txt"
    
    # Read the file and convert it to hexadecimal
    hex_data = read_file_hex(input_file_path)

    if hex_data:
        # Extract UDP packets from the hexadecimal data
        udp_packets = extract_udp_packets(hex_data)
        
        if udp_packets:
            print("Extracted UDP packets:")
            for packet in udp_packets:
                print(packet)
        else:
            print("No UDP packets were found in the file.")