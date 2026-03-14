"""
This file outlines the function of files in this folder


alerting.py:

Handles notification dispatching when findings come in. dispatch_alert() should
be called in the pipeline after a finding has been saved. Parameter 'channels' specifies
which channels the notification should be sent to. Channels are any function with
arguments (Finding, Severity) -> None. The alert must also pass the security threshold parameter
in order for a notification to be triggered.

"""
