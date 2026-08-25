package org.bouncycastle.crypto.signers.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

class LmsUtils
{
    public static void u32str(int n, Digest d)
    {
        d.update((byte)(n >>> 24));
        d.update((byte)(n >>> 16));
        d.update((byte)(n >>> 8));
        d.update((byte)(n));
    }

    public static void u16str(short n, Digest d)
    {
        d.update((byte)(n >>> 8));
        d.update((byte)(n));
    }

    public static void byteArray(byte[] array, Digest digest)
    {
        digest.update(array, 0, array.length);
    }

    public static void byteArray(byte[] array, int start, int len, Digest digest)
    {
        digest.update(array, start, len);
    }

    public static int calculateStrength(LMSParameters lmsParameters)
    {
        if (lmsParameters == null)
        {
            throw new NullPointerException("lmsParameters cannot be null");
        }

        LMSigParameters sigParameters = lmsParameters.getLMSigParam();
        return (1 << sigParameters.getH()) * sigParameters.getM();
    }
}
