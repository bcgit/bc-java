package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.CMCEPrivateKey;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCCMCEPrivateKey
    implements CMCEPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient CMCEPrivateKeyParameters params;

    private transient String algorithm;

    public BCCMCEPrivateKey(
        CMCEPrivateKeyParameters params)
    {
        init(params);
    }

    public BCCMCEPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.params = (CMCEPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.algorithm = CMCEParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    private void init(CMCEPrivateKeyParameters params)
    {
        this.params = params;
        this.algorithm = CMCEParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCCMCEPrivateKey)
        {
            BCCMCEPrivateKey otherKey = (BCCMCEPrivateKey)o;

            return Arrays.constantTimeAreEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        // ISO CMCE private keys do not embed the public key and pk reconstruction is not exposed on CMCEEngine.
        return getAlgorithm().hashCode();
    }

    /**
     * @return name of the algorithm - "CMCE..." followed by the parameter type.
     */
    public final String getAlgorithm()
    {
        return algorithm;
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

    public CMCEParameterSpec getParameterSpec()
    {
        return CMCEParameterSpec.fromName(params.getParameters().getName());
    }

    CMCEPrivateKeyParameters getKeyParams()
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
