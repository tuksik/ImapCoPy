An IMAP mailbox synchronisation tool
====================================

This tool synchronises IMAP mailboxes for mail server migration.
Written originally to migrate from Zimbra to Dovecot, this tool may contain idiosyncrasies of these servers.

Contrary to most sync tools out there, this one does not require the knowledge of the users' password, only of a master
user for both sides. This allows unattended migrations.

Requirements
------------
This script *requires* python 3.4 or above. Lower-versioned will have problems with unicode/bytes/string coercion.

Note
----
This script has been built for my personal migration and is almost certainly not suitable for yours. It may be a good 
starting point to writing your own sync tool, or may evolve in something more flexible.

License
-------
This is released in the public domain.

TODO
----
### Testing
A lot is left to do but the first one will be testing. I am planning to write a test harness that comprises a dovecot
and a UW server, but nothing really exists there yet.

### Functionality
Functionality is limited by the requirements I had at the time. Interesting things to add would be reliable two-ways
synchronisation, including deleted messages, faster resync, auto batch size detection, performance statistics,
the capability to treat several mailboxes instead of just two, multiprocessing, ...

### API and code structure
The api is all over the place at the moment, and will need a serious overhaul before this becomes flexible enough to do
a lot more than what my initial need was.
Similarly the code structure is messy, needs reorganising big time.

### imaplib work
Imaplib is cool but has a little too close-to-the-metal api for my liking. 
I need to choose to either replace imaplib functionality
where relevant (there are a couple of places where I need to 'cheat' to get imaplib to do what I want it to) and/or
write a higher level api to it.

### protocol understanding and knowledge
The UIDValidity responses' role is not well understood for instance. It is simply ignored for now. My migrations being
rather atomic, it's not a huge deal, but I'm pretty sure it can break in interesting ways, possibly loosing data.

### documentation
A lot more doc is required.

### concurrency
consider concurrent access to mailboxes. What happens when someones deletes/updates a message mid-flight?

### security
  * no passwords on the cli
  * input and data validation need a lot more robustness

How to use (CLI)
----------------
The usage is returned by calling the script with the `-h` argument.

    usage: syncimap.py [-h]
                   source_user source_master_user source_master_password
                   source_server destination_user destination_master_user
                   destination_master_password destination_server
    
    positional arguments:
      source_user
      source_master_user
      source_master_password
      source_server
      destination_user
      destination_master_user
      destination_master_password
      destination_server
    
    optional arguments:
      -h, --help            show this help message and exit
      
      
