flowd is a small, fast and secure NetFlow™ collector. It offers the following features:

  * Understands NetFlow protocol v.1, v.5, v.7 and v.9 (including IPv6 flows)
  * Supports both IPv4 and IPv6 transport of flows
  * Secure: flowd is privilege separated to limit the impact of any compromise
  * Supports filtering and tagging of flows, using a packet filter-like syntax
  * Stores recorded flow data in a compact binary format which supports run-time choice over which flow fields are stored
  * Ships with both Perl and Python interfaces for reading and parsing the on-disk record format
  * Is licensed under a liberal BSD-like license
  * Supports reception of flow export datagrams sent to multicast groups (IPv4 and IPv6), thereby allowing the construction of redundant flow collector systems

flowd works with any standard NetFlow exporter, including hardware devices (e.g. routers) or software flow tracking agents, such as my own softflowd and pfflowd. Please refer to the README for more information.

The flowd sensor follows the Unix philosophy of "doing one thing well" - it doesn't try to do anything beyond accepting NetFlow packets and storing them in a standard format on disk. In particular, it does not include support for storing flows in multiple formats or performing data analysis. That sort of thing is left to external tools. The source distribution includes several example tools including a basic reporting script and one to store flows in a SQL database.