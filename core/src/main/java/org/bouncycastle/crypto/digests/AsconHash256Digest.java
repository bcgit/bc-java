package org.bouncycastle.crypto.digests;

/**
 * ASCON v1.2 Digest, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 Digest with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 */
public class AsconHash256Digest
    extends AsconBaseDigest
{
    public AsconHash256Digest()
    {
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon Hash 256";
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        return hash(output, outOff, CRYPTO_BYTES);
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        x0 = -7269279749984954751L;
        x1 = 5459383224871899602L;
        x2 = -5880230600644446182L;
        x3 = 4359436768738168243L;
        x4 = 1899470422303676269L;
    }
}
