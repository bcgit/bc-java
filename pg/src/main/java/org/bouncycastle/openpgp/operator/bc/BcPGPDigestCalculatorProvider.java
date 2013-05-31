package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public class BcPGPDigestCalculatorProvider
    implements PGPDigestCalculatorProvider
{
    public PGPDigestCalculator get(final int algorithm)
        throws PGPException
    {
        final Digest dig = BcImplProvider.createDigest(algorithm);

        final DigestOutputStream stream = new DigestOutputStream(dig);

        return new PGPDigestCalculator()
        {
            public int getAlgorithm()
            {
                return algorithm;
            }

            public OutputStream getOutputStream()
            {
                return stream;
            }

            public byte[] getDigest()
            {
                return stream.getDigest();
            }

            public void reset()
            {
                dig.reset();
            }
        };
    }

    private class DigestOutputStream
        extends OutputStream
    {
        private Digest dig;

        DigestOutputStream(Digest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws IOException
        {
            dig.update(bytes, 0, bytes.length);
        }

        public void write(int b)
            throws IOException
        {
            dig.update((byte)b);
        }

        byte[] getDigest()
        {
            byte[] d = new byte[dig.getDigestSize()];

            dig.doFinal(d, 0);

            return d;
        }
    }
}