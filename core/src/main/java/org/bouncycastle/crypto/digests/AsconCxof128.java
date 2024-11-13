package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;

/**
 * ASCON v1.2 XOF, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 XOF with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 */
public class AsconCxof128
    extends AsconBaseDigest
    implements Xof
{
    private byte[] s;

    public AsconCxof128(byte[] s)
    {
        if (s.length > 2048)
        {
            throw new DataLengthException("customized string is too long");
        }
        this.s = Arrays.clone(s);
        reset();
    }

    public AsconCxof128(byte[] s, int off, int len)
    {
        if ((off + len) > s.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if (len > 2048)
        {
            throw new DataLengthException("customized string is too long");
        }
        this.s = Arrays.copyOfRange(s, off, off + len);
        reset();
    }

    public AsconCxof128()
    {
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon-XOF-128";
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {

        if (CRYPTO_BYTES + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        if (s != null)
        {
            absorb(s, s.length);
        }
        absorb(buffer.toByteArray(), buffer.size());
        /* squeeze full output blocks */
        squeeze(output, outOff, outLen);
        return outLen;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        return doOutput(output, outOff, getDigestSize());
    }

    @Override
    public int doFinal(byte[] output, int outOff, int outLen)
    {
        return doOutput(output, outOff, outLen);
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        x0 = 7445901275803737603L;
        x1 = 4886737088792722364L;
        x2 = -1616759365661982283L;
        x3 = 3076320316797452470L;
        x4 = -8124743304765850554L;
    }
}

