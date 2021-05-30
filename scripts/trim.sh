#!/bin/sh
# script to remove JDK 1.5+ generics from a file

(
ed $1 <<%%
g/<[A-Z?][^>@]*[a-zA-Z0-9]>/s///g
g/<[A-Z]>/s///g
g/<[a-z][a-z]*\\[\\]>/s///g
g/List>/s//List/g
g/<AlgorithmIdentifier, byte\\[\\]>/s///g
g/ERSData\\.\\.\\./s//ERSData[]/g
g/Collections.singletonList(dataObject)/s//new ArrayList(); dataObjects.add(dataObject)/g
w
q
%%
) > /dev/null 2>&1
