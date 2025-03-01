import socket
from collections import Counter
import matplotlib.pyplot as plt
import json

# Step 1: Read the file and convert it to hexadecimal
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


# Step 2: Extract UDP packets
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


# Step 3: Analyze payloads for DDoS activity
def analyze_payloads(udp_packets):
    """
    Analyzes the payloads of UDP packets for patterns or anomalies.
    """
    payload_counts = Counter(udp_packets)

    # Define a threshold for suspicious activity
    threshold = 5  # Example: More than 5 identical payloads is suspicious

    print("Analyzing payloads...")
    suspicious_payloads = {
        payload: count
        for payload, count in payload_counts.items()
        if count > threshold
    }

    if suspicious_payloads:
        print("Potential DDoS activity detected:")
        for payload, count in suspicious_payloads.items():
            print(f"Suspicious payload (Count: {count}): {payload[:50]}...")  # Show first 50 chars
    else:
        print("No suspicious activity detected.")


# Step 4: Save extracted packets to a file
def save_packets_to_file(udp_packets, output_file):
    """
    Saves extracted UDP packets to a file.
    """
    with open(output_file, 'w') as file:
        for packet in udp_packets:
            file.write(packet + '\n')
    print(f"Saved {len(udp_packets)} UDP packets to {output_file}")


# Step 5: Replay packets (for testing purposes only)
def replay_packets(udp_packets, target_ip, target_port):
    """
    Replays UDP packets to a target IP and port.
    WARNING: Use this responsibly and only in a controlled environment.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Replaying {len(udp_packets)} UDP packets to {target_ip}:{target_port}")

    try:
        for packet in udp_packets:
            # Convert hex string back to bytes
            packet_bytes = bytes.fromhex(packet)
            sock.sendto(packet_bytes, (target_ip, target_port))
        print("Replay completed.")
    except Exception as e:
        print(f"Error during replay: {e}")
    finally:
        sock.close()


# Step 6: Visualize packet lengths
def visualize_packet_lengths(udp_packets):
    """
    Visualizes the distribution of packet lengths.
    """
    lengths = [len(packet) for packet in udp_packets]

    plt.hist(lengths, bins=20, color='blue', edgecolor='black')
    plt.title("Distribution of UDP Packet Lengths")
    plt.xlabel("Packet Length (bytes)")
    plt.ylabel("Frequency")
    plt.show()


# Step 7: Export results to JSON
def export_results(udp_packets, output_file):
    """
    Exports UDP packet data to a JSON file.
    """
    with open(output_file, 'w') as file:
        json.dump(udp_packets, file, indent=4)
    print(f"Exported {len(udp_packets)} UDP packets to {output_file}")


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
            print(f"Extracted {len(udp_packets)} UDP packets.")

            # Analyze payloads for potential DDoS activity
            analyze_payloads(udp_packets)

            # Save packets to a file
            save_packets_to_file(udp_packets, "extracted_udp_work_packets.txt")

            # Visualize packet lengths
            visualize_packet_lengths(udp_packets)

            # Export results to JSON
            export_results(udp_packets, "udp_packets.json")

            # Optional: Replay packets (for educational purposes only)
            # Uncomment and modify the target IP and port
            # WARNING: Ensure this is done in a controlled environment!
            # replay_packets(udp_packets, "127.0.0.1", 12345)

        else:
            print("No UDP packets were found in the file.")