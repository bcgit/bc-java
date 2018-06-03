package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * BSI Key Derivation Function for Session Keys (see BSI-TR-03111 Section 4.3.3)
 */
public class GSKKFDGenerator
    implements DigestDerivationFunction
{
    private final Digest digest;

    private byte[] z;
    private int counter;
    private byte[] r;

    private byte[] buf;

    public GSKKFDGenerator(Digest digest)
    {
        this.digest = digest;
        this.buf = new byte[digest.getDigestSize()];
    }

    public Digest getDigest()
    {
        return digest;
    }

    public void init(DerivationParameters param)
    {
        if (param instanceof GSKKDFParameters)
        {
            this.z = ((GSKKDFParameters)param).getZ();
            this.counter = ((GSKKDFParameters)param).getStartCounter();
            this.r = ((GSKKDFParameters)param).getNonce();
        }
        else
        {
            throw new IllegalArgumentException("unkown parameters type");
        }
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        if (outOff + len > out.length)
        {
            throw new DataLengthException("output buffer too small");
        }

        digest.update(z, 0, z.length);

        byte[] c = Pack.intToBigEndian(counter++);

        digest.update(c, 0, c.length);

        if (r != null)
        {
            digest.update(r, 0, r.length);
        }

        digest.doFinal(buf, 0);

        System.arraycopy(buf, 0, out, outOff, len);

        Arrays.clear(buf);

        return len;
    }
}
