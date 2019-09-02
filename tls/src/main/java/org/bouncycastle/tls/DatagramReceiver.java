package org.bouncycastle.tls;

import java.io.IOException;

public interface DatagramReceiver
{
    int getReceiveLimit() throws IOException;

    int receive(byte[] buf, int off, int len, int waitMillis) throws IOException;
}
