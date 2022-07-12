package org.bouncycastle.pqc.crypto.ntru;

/**
 * Class for return values of {@link NTRUOWCPA#decrypt}.
 */
class OWCPADecryptResult
{
    final byte[] rm;
    final int fail;

    public OWCPADecryptResult(byte[] rm, int fail)
    {
        this.rm = rm;
        this.fail = fail;
    }
}
