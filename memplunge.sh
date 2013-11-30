#!/bin/bash
# Information disclosure searcher/debugger written by ewilded
# This script conducts search over the whole memory allocated by all existing processes (and optionally opened file descriptors), looking for particular string.
# The initial application of this script was to facilitate the process of discovering various dependancies and potential information disclosure vulnerabilities. The idea is to put the string which's flow we are interested in into the input of relevant application/service and then look for it in the memory. 
# For instance, we can use the passwd command to change our password and then find out if any process stored it in the memory. 
# We can write some unique marker string into some network service's socket and see where it is stored.
# We can also use it to search the memory for suspected values we are informed might indicate a rootkit/backdoor.
# Problems: of course this method won't catch values that are:
# - stored and erased from the memory immediately (before the memory dump occurs)
# - saved into a file and then have the file's descriptor closed immediately (these will require full disk search, which is painfull unless the testing environment is properly prepared for this particular purpose - nevertheless it would be good idea to put modification time condition on the find command in such scenario, and use grep as its subordinate command triggered with -exec switch)

#TODO
# test new features (files search, include exclude options)
# conduct some funny research against various system services
# CONFIGURATION:
NEEDLE="THISISMYN33DLE"
PID="ALL"
OUTDIR="/mnt/hgfs/PT/memdive"
EXCLUDE="lib"
INCLUDE=""
SEARCH_OPEN_FILES="YES"
SHRED_AFTER_SEARCH="NO" # turning off shred speeds up the search, but it involves more potential for information disclosure


function memdive()
{
	CMD=""
	if [ "$INCLUDE" != "" ]; then 
		CMD="grep $INCLUDE /proc/$PID/maps"
	fi;
	if [ "$EXCLUDE" != "" ]; then
		CMD="grep -v $EXCLUDE /proc/$PID/maps"
	fi;
	eval "$CMD"| sed 's/-/ /'| while read start stop rest; do
		OUTPATH="$OUTDIR/$PID.$start.$stop.mem"
		gdb --batch --pid $PID -ex "dump memory $OUTPATH 0x$start 0x$stop" 1>&2 1>/dev/null
		OUTPUT=`grep $NEEDLE $OUTPATH`
		if [ "$OUTPUT" != "" ]; then
			echo "Needle $NEEDLE found in $NAME (PID:$PID) in 0x$start-0x$stop ($rest)."
		else
			if [ "$SHRED_AFTER_SEARCH" == "YES" ]; then
				shred $OUTPATH
			fi;
			rm -rf $OUTPATH
		fi;
	done;
}

function filedive
{
	lsof -p $PID|while read cmd pid user fd type dev size node name; do					
	if [[ "$type" == "REG" && $fd =~ ^[0-9]+r$ ]]; then
		FILEOUTPUT=`grep $NEEDLE $name`
		if [ "$FILEOUTPUT" != "" ]; then
			echo "Needle $NEEDLE found in $name (file belongs to $NAME ($PID)"
		fi;
	fi;
	done;
}

if [ "$PID" == "ALL" ]; then
	for PID in `ps axu | awk '//{print $2}'`; do
		if [ "$PID" != "$$" ]; then
				NAME=`cat /proc/$PID/comm`
				memdive $PID 
				if [ "$SEARCH_OPEN_FILES" == "YES" ]; then
					filedive $PID
				fi;
			else
			echo "Skipping self process $$"
		fi;
	done;
else
		NAME=`cat /proc/$PID/comm`
		memdive $PID
		if [ "$SEARCH_OPEN_FILES" == "YES" ]; then
			filedive $PID
		fi;
fi;