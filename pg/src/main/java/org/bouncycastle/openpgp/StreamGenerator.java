package org.bouncycastle.openpgp;

import java.io.IOException;

interface StreamGenerator
{
    void close()
        throws IOException;
}
