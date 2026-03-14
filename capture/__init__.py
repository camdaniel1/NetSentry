"""
This file outlines the function of the files in this folder:


interfaces.py: 

Primarily a utility class to fetch network data from the correct interface.
list_interfaces() enumerates capturable interfaces and find_interface() translates
an interface IP/Human name/System name into a generic type (InterfaceInfo).


sniffer.py

Fetched interfaces can be passed into a Sniffer() object given the pcap_name
to read network traffic on that interface. This file reads all network traffic and
stores it into a queue with each packet normalized into a generic type (RawPacket).
By calling sniffer.packet_queue.get(), you can fetch network packet data on the
interface one at a time.


pcap_writer.py

This file takes network packets that have been fetched by sniffer.py and writes them
to a running PCAP file. Upon initializing the PcapWriter object, this file handles the
write file location and a thread lock. By calling the write() function, you can write
packets to the running PCAP file one at a time. A PcapLocation dataclass object is returned
for each packet written to the PCAP file.


packet_normalizer.py

Upon invoking normalize_packet(RawPacket), this file converts a RawPacket
into a single NormalizedPacket model. After packets have been normalized, they are suitable
to be processed by detectors by invoking detector.process_packet(packet)

"""
