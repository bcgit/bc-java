package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{

    public byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public FalconPublicKeyParameters(FalconParameters param, byte[] publicKey)
    {
        super(false, param);
        this.publicKey = publicKey;
    }

    FalconPublicKeyParameters(FalconParameters param, FalconShortPoly pubKey)
    {
        super(false, param);
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        int pksize = ((14 * n) >> 3) + 1;
        this.publicKey = new byte[pksize]; // 14n/8 bytes + 1 header byte
        for (int i = 0; i < pksize; i++)
        { // zero array
            this.publicKey[i] = 0;
        }
        // generate header - 0 0 0 0 logn
        this.publicKey[0] |= (byte)logn;
        // generate body - 14 bit coefficients
        int buf = 1;
        int acc = 0;
        int acc_len = 0;
        for (int u = 0; u < n; u++)
        {
            acc = (acc << 14) | pubKey.coeffs[u];
            acc_len += 14;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                this.publicKey[buf++] = (byte)(acc >> acc_len);
            }
        }
        if (acc_len > 0)
        {
            this.publicKey[buf] = (byte)(acc << (8 - acc_len));
        }
    }

    public byte[] getEncoded()
    {
        return this.getPublicKey();
    }

    FalconShortPoly get_h()
    {
        int n = 1 << this.getParam().getLogn();
        short[] h = new short[n];
        int buf = 1;
        int acc = 0;
        int acc_len = 0;
        int u = 0;
        while (u < n)
        {
            acc = (acc << 8) | Byte.toUnsignedInt(this.publicKey[buf++]);
            acc_len += 8;
            if (acc_len >= 14)
            {
                int w;

                acc_len -= 14;
                w = (acc >>> acc_len) & 0x3FFF;
                h[u++] = (short)w;
            }
        }
        return new FalconShortPoly(h);
    }
}
