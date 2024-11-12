package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;

/**
 * ASCON v1.2 XOF, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 XOF with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 */
public class AsconCxof128
    extends AsconDefaultDigest
    implements Xof
{
    public AsconCxof128()
    {
        reset();
    }

    private final ByteArrayOutputStream customizedString = new ByteArrayOutputStream();


    @Override
    public String getAlgorithmName()
    {
        return "Ascon-XOF-128";
    }


    public void updateCustomizedString(byte in)
    {
        customizedString.write(in);
    }

    public void updateCustomizedString(byte[] input, int inOff, int len)
    {
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        customizedString.write(input, inOff, len);
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {
        if (CRYPTO_BYTES + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        int customizedStringLen = customizedString.size();
        if (customizedStringLen > 2048)
        {
            throw new DataLengthException("customized string is too long");
        }
        absorb(customizedString.toByteArray(), customizedStringLen);
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
        customizedString.reset();
        buffer.reset();
        /* initialize */
        x0 = 7445901275803737603L;
        x1 = 4886737088792722364L;
        x2 = -1616759365661982283L;
        x3 = 3076320316797452470L;
        x4 = -8124743304765850554L;
    }
}

