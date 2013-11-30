# Information disclosure searcher/debugger written by ewilded
# This script conducts search over the whole memory allocated by all existing processes (and optionally opened file descriptors), looking for particular string.
# The initial application of this script was to facilitate the process of discovering various dependancies and potential information disclosure vulnerabilities. The idea is to put the string which's flow we are interested in into the input of relevant application/service and then look for it in the memory. 
# For instance, we can use the passwd command to change our password and then find out if any process stored it in the memory. 
# We can write some unique marker string into some network service's socket and see where it is stored.
# We can also use it to search the memory for suspected values we are informed might indicate a rootkit/backdoor.
# Problems: of course this method won't catch values that are:
# - stored and erased from the memory immediately (before the memory dump occurs)
# - saved into a file and then have the file's descriptor closed immediately (these will require full disk search, which is painfull unless the testing environment is properly prepared for this particular purpose - nevertheless it would be good idea to put modification time condition on the find command in such scenario, and use grep as its subordinate command triggered with -exec switch)
