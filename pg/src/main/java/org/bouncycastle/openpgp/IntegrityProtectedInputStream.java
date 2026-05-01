package org.bouncycastle.openpgp;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.util.Exceptions;

/**
 * {@link InputStream} that performs verification of integrity protection upon {@link #close()}.
 */
public class IntegrityProtectedInputStream
        extends FilterInputStream
{

    private final PGPEncryptedData esk;

    public IntegrityProtectedInputStream(InputStream in, PGPEncryptedData dataPacket)
    {
        super(in);
        this.esk = dataPacket;
    }

    @Override
    public int read()
            throws IOException
    {
        int i = in.read();
        if (i == -1)
        {
            close();
        }
        return i;
    }

    @Override
    public int read(byte[] b)
            throws IOException
    {
        int r = in.read(b);
        if (r == -1)
        {
            close();
        }
        return r;
    }

    @Override
    public int read(byte[] b, int off, int len)
            throws IOException
    {
        int r = in.read(b, off, len);
        if (r == -1)
        {
            close();
        }
        return r;
    }

    @Override
    public void close()
            throws IOException
    {
        super.close();
        if (esk.getEncData() instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) esk.getEncData();
            if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
            {
                try
                {
                    if (!esk.verify())
                    {
                        throw new PGPException("Malformed integrity protected data.");
                    }
                }
                catch (PGPException e)
                {
                    throw Exceptions.ioException(e.getMessage(), e);
                }
            }
        }
    }
}
