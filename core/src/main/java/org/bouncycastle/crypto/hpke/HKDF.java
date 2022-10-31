package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class HKDF
{

    private final Digest hash;
    private static final short KDF_HKDF_SHA256 = 0x0001;
    private static final short KDF_HKDF_SHA384 = 0x0002;
    private static final short KDF_HKDF_SHA512 = 0x0003;
    private final static String versionLabel = "HPKE-v1";

    public HKDF(short kdfId)
        throws Exception
    {
        switch (kdfId)
        {
            case KDF_HKDF_SHA256:
                hash = new SHA256Digest();
                break;
            case KDF_HKDF_SHA384:
                hash = new SHA384Digest();
                break;
            case KDF_HKDF_SHA512:
                hash = new SHA512Digest();
                break;
            default:
                throw new Exception("Unknown kdf id");
        }
    }

    protected int getHashSize()
    {
        return hash.getDigestSize();
    }
    private byte[] Expand(byte[] prk, byte[] info, int outLen)
    {
        HMac hmac = new HMac(hash);

        byte[] t = new byte[hmac.getMacSize()];
        byte n = 1;
        byte[] buf = new byte[((outLen/ t.length)+1)*t.length];
        int dataLen = 0;

        while(dataLen < outLen)
        {
            hmac.init(new KeyParameter(prk));//todo: init outside and reset here???
            if (n != 1)
            {
                hmac.update(t, 0, t.length);
            }

            hmac.update(info, 0, info.length);
            hmac.update(n);
//            ////System.out.println(n);
            hmac.doFinal(t, 0);
//            ////System.out.println("t: "+ Hex.toHexString(t));
            System.arraycopy(t, 0, buf, (n-1)*t.length, t.length);
            dataLen += t.length;
            n++;
        }
        return Arrays.copyOf(buf, outLen);
    }

    private byte[] Extract(byte[] salt, byte[] ikm)
    {
        if (salt == null)
        {
            salt = new byte[hash.getDigestSize()];
        }

        HMac hmac = new HMac(hash);
        hmac.init(new KeyParameter(salt));

        byte[] out = new byte[hmac.getMacSize()];
        hmac.update(ikm, 0, ikm.length);
        hmac.doFinal(out, 0);
        return out;
    }


    // todo remove suiteID
    protected byte[] LabeledExtract(byte[] salt, byte[] suiteID, String label, byte[] ikm)
    {
        byte[] labeledIKM = Arrays.concatenate(versionLabel.getBytes(), suiteID, label.getBytes(), ikm);
        return Extract(salt, labeledIKM);
    }

    // todo remove suiteID
    protected byte[] LabeledExpand(byte[] prk, byte[] suiteID, String label, byte[] info, int L)
            throws Exception
    {
        if (L > (1 << 16))
        {
            throw new Exception("Expand length cannot be larger than 2^16");
        }
        byte[] labeledInfo = Arrays.concatenate(Pack.shortToBigEndian((short) L), versionLabel.getBytes(), suiteID, label.getBytes());
        labeledInfo = Arrays.concatenate(labeledInfo, info);
        return Expand(prk, labeledInfo, L);
    }


}
