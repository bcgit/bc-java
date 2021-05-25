package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.crypto.TlsHMAC;

final class BcTlsHMAC
    implements TlsHMAC
{
    private final HMac hmac;

    BcTlsHMAC(HMac hmac)
    {
        this.hmac = hmac;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        hmac.init(new KeyParameter(key, keyOff, keyLen));
    }

    public void update(byte[] input, int inOff, int length)
    {
        hmac.update(input, inOff, length);
    }

    public byte[] calculateMAC()
    {
        byte[] rv = new byte[hmac.getMacSize()];

        hmac.doFinal(rv, 0);

        return rv;
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        hmac.doFinal(output, outOff);
    }

    public int getInternalBlockSize()
    {
        return ((ExtendedDigest)hmac.getUnderlyingDigest()).getByteLength();
    }

    public int getMacLength()
    {
        return hmac.getMacSize();
    }

    public void reset()
    {
        hmac.reset();
    }
}
