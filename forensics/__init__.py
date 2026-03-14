"""
This file outlines the functions of other files in this folder.


timeline.py:

build_timeline(id) is used to create an IncidentTimeline type by combining all
database objects with the same incident_id. Grouping must have already been
ran for this to take place. The IncidentTimeline object contains various data
compiled from all the findings.


report.py:

Contains functions to turn an IncidentTimeline object into either a dict or markdown.

export_report(id) creates the IncidentTimeline object with the given incident_id and
exports it to either the specified output directory or REPORTS_DIR. The export format
can either be json or markdown.


session_replay.py:

replay_host(ip) gets all incident findings from the source ip, places the findings in
chronological order, and then returns a HostSessionReplay object. This record contains
every incident_id this host has been a part of and whether they span multiple incidents.

For example, an ip may cause an incident then 2 weeks later cause another. Although these
have different incident ids, they would show that this host is a repeat offender. This is
different than session_tracker.py, which just shows info about a host and if they have multiple
findings. session_replay.py shows whether their multiple findings were during distinct
periods of time.

"""