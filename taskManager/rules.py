from fodtlmon_middleware.sysmon import *

# Define your Interpreted predicates here

# Add your http request rules here
Sysmon.add_http_rule("test", "G(true)")
