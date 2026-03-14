"""
This file outlines the functions of files in this folder:


severity.py:

Includes scoring for how critical each incident is deemed to be. Each detector
has it's own separate scoring logic. A hashtable (_SCORERS) mapping detector names
to functions determines which logic is used when the score function is invoked.
core/event.py uses function Event.from_finding(finding) to create a new event,
and this function automatically computes the severity scoring of the incident upon
creation of the event. 

Events should also have evidence attach to them which should be created using the
attach_evidence() function, which stores the incident packet.


grouper.py:

When the packet queue is empty and a certain amount of time has passed since the last
run, pipeline.py will determine if run_grouping() should be automatically done. This
function will only work of findings that are not already grouped, as determined by
storage/event_store.get_ungrouped_findings(). grouper.py will then create clusters
by invoking the internal _cluster_by_ip_and_time() function. Each cluster (every related incident)
is then assigned the same incident_id by run_grouping() and stored as such in the incident database.

By looking up this incident_id, you will be able to see all related **incident** traffic.


session_tracker.py

Session tracker allows looking up ALL INCIDENTS associated with a host.
get_repeat_offenders() determines which hosts are the most malicious and
summarize_host(ip) is used to fetch all incidents and their info from a given host.

TODO: This should be changed to be able to fetch ALL TRAFFIC from a given host, which
      is currently being stored in PCAP files.

"""