package org.bouncycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NHPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class BCNHPrivateKey
    implements NHPrivateKey
{
    private static final long serialVersionUID = 1L;
    ;
    private final NHPrivateKeyParameters params;

    public BCNHPrivateKey(
        NHPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.params = (NHPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this NH private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (!(o instanceof BCNHPrivateKey))
        {
            return false;
        }
        BCNHPrivateKey otherKey = (BCNHPrivateKey)o;

        return Arrays.areEqual(params.getSecData(), otherKey.params.getSecData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getSecData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public short[] getSecretData()
    {
        return params.getSecData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private static short[] convert(byte[] octets)
    {
        short[] rv = new short[octets.length / 2];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Pack.littleEndianToShort(octets, i * 2);
        }

        return rv;
    }
}
