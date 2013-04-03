pan-demonium
=================

pan-demonium is a python script that uses unix command-line-tools find, grep and egrep for 
searching the local filesystem for Primary Account Numbers(PANs) using different regular expressions 
that matches PANs for the major card branches.

pan-demonium then lists all found PANs together with the card branch to which that PAN belongs 
and can send notifications via email and syslog.

    - American Express (amex)
    - Discover (discover)
    - Mastercard (mastercard)
    - VISA (visa)

