package com.github.gv2011.bcasn.crypto.tls;

import java.io.IOException;

interface DTLSHandshakeRetransmit
{
    void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
        throws IOException;
}
