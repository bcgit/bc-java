package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * {@link InputStream} that performs verification of integrity protection upon {@link #close()}.
 */
public class VerifyingInputStream
        extends FilterInputStream
{

    private final PGPEncryptedData esk;

    public VerifyingInputStream(InputStream in, PGPEncryptedData dataPacket)
    {
        super(in);
        this.esk = dataPacket;
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
                    throw new IOException(e);
                }
            }
        }
    }
}
