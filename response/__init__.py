"""
This file outlines the function of files in this folder


alerting.py:

Handles notification dispatching when findings come in. dispatch_alert() should
be called in the pipeline after a finding has been saved. Parameter 'channels' specifies
which channels the notification should be sent to. Channels are any function with
arguments (Finding, Severity) -> None. The alert must also pass the security threshold parameter
in order for a notification to be triggered.

webhook_channel(URL) is used to post the alert as JSON to the given URL.


containment.py

Handles options to block the threat. After an alert has been dispatched in the pipeline the
maybe_contain() function can determine whether to contain the finding. If the severity threshold
on the alert is reached, a command will be run to block the IP.

No other containment implementation has been created at the moment besides blocking.
"""