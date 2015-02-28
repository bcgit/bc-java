#!/bin/sh
# script to remove JDK 1.5+ generics from a file

ed $1 <<%%
g/<[a-zA-Z?][^>@]*[a-zA-Z0-9]>/s///
g/<[a-zA-Z]>/s///
w
q
%%
