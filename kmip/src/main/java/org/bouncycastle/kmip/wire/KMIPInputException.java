package org.bouncycastle.kmip.wire;

import java.io.IOException;

public class KMIPInputException
    extends IOException
{
    public KMIPInputException(String msg)
    {
        super(msg);
    }
}
