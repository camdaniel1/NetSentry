"""
This file outlines how this folder is used


base.py:

Interface file for detectors. Generic detection results are stored as Finding objects.
A Finding is used only where detections flag that there is legitimately something
suspiscious with network data, otherwise the packets are discarded. process_packet()
returns a Finding if a singular packet triggers a detection, and flush() is used
when multiple packets are needed.


use:

In the pipeline, a list of detectors (Detector type) are stored as registered. Each registered
detector then runs its process_packet() function and determines if a finding was made. If a
finding is noted, it can then be scored and have subsequent actions called later down the pipeline.
The detector simply just creates these findings.

*** BEFORE A DETECTOR CAN PROCESS PACKETS THEY MUST BE PARSED USING THE PROTOCOL PARSER ***
------------------------------------------------------------------------------------------------


"""