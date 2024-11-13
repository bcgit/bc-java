package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Xof;

/**
 * ASCON v1.2 XOF, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 XOF with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 *
 */
public class AsconXof128
    extends AsconBaseDigest
    implements Xof
{
    public AsconXof128()
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
        return hash(output, outOff, outLen);
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
    public int getByteLength()
    {
        return 8;
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        x0 = -2701369817892108309L;
        x1 = -3711838248891385495L;
        x2 = -1778763697082575311L;
        x3 = 1072114354614917324L;
        x4 = -2282070310009238562L;
    }
}

