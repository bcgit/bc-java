#!/bin/sh
# script to remove JDK 1.5+ generics from a file

(
ed $1 <<%%
g/org.bouncycastle.jce.cert./s//java.security.cert./g
w
q
%%
) > /dev/null 2>&1
