"""
This file explains how the pipeline operates

pipeline.py:

interfaces -> sniffer -> pcap_writer -> storage
                      -> packet_normalizer -> detectors -> event.py (if detection)

"""
