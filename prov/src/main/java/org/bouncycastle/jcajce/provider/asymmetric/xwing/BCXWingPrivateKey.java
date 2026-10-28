package org.bouncycastle.jcajce.provider.asymmetric.xwing;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XWingPrivateKey;
import org.bouncycastle.jcajce.interfaces.XWingPublicKey;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

public class BCXWingPrivateKey
    implements XWingPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient XWingPrivateKeyParameters params;

    public BCXWingPrivateKey(XWingPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCXWingPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.params = (XWingPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXWingPrivateKey)
        {
            BCXWingPrivateKey otherKey = (BCXWingPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getSeed(), otherKey.params.getSeed());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    public XWingPublicKey getPublicKey()
    {
        return new BCXWingPublicKey(params.getPublicKeyParameters());
    }

    /**
     * @return name of the algorithm - "X-WING".
     */
    public final String getAlgorithm()
    {
        return "X-WING";
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

    XWingPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
