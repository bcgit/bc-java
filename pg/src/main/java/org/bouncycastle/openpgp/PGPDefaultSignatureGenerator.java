package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;

abstract class PGPDefaultSignatureGenerator
{
    protected byte lastb;
    protected OutputStream sigOut;
    protected int sigType;

    public void update(
        byte b)
    {
        if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\r')
            {
                byteUpdate((byte)'\r');
                byteUpdate((byte)'\n');
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    byteUpdate((byte)'\r');
                    byteUpdate((byte)'\n');
                }
            }
            else
            {
                byteUpdate(b);
            }

            lastb = b;
        }
        else
        {
            byteUpdate(b);
        }
    }

    public void update(
        byte[] b)
    {
        this.update(b, 0, b.length);
    }

    public void update(
        byte[]  b,
        int     off,
        int     len)
    {
        if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            int finish = off + len;

            for (int i = off; i != finish; i++)
            {
                this.update(b[i]);
            }
        }
        else
        {
            blockUpdate(b, off, len);
        }
    }

    private void byteUpdate(byte b)
    {
        try
        {
            sigOut.write(b);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    protected void blockUpdate(byte[] block, int off, int len)
    {
        try
        {
            sigOut.write(block, off, len);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException("unable to update signature: " + e.getMessage(), e);
        }
    }
}
