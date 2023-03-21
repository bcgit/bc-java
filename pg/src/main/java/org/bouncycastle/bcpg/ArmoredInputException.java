package org.bouncycastle.bcpg;

import java.io.IOException;

public class ArmoredInputException
    extends IOException
{
    public ArmoredInputException(String msg)
    {
        super(msg);
    }
}
