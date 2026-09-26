package org.bouncycastle.pqc.jcajce.provider.sdith;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.NamedParameterSpecUtil;
import org.bouncycastle.pqc.crypto.sdith.SDitHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SDitHKey;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCSDitHPrivateKey
    implements PrivateKey, SDitHKey
{
    private static final long serialVersionUID = 1L;

    private transient SDitHPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSDitHPrivateKey(SDitHPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSDitHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SDitHPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCSDitHPrivateKey)
        {
            BCSDitHPrivateKey otherKey = (BCSDitHPrivateKey)o;
            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCSDitHPublicKey getPublicKey()
    {
        return new BCSDitHPublicKey(params.getPublicKeyParameters());
    }

    public final String getAlgorithm()
    {
        return Strings.toUpperCase(params.getParameters().getName());
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);
            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    /**
     * Return the parameter set of this key as a java.security.spec.NamedParameterSpec, the form the
     * JDK's own keys report through java.security.AsymmetricKey.getParams() from Java 22.
     *
     * @return a NamedParameterSpec naming the parameter set on Java 11 and later, null otherwise.
     */
    public AlgorithmParameterSpec getParams()
    {
        return NamedParameterSpecUtil.getNamedParameterSpec(getParameterSpec().getName());
    }

    public SDitHParameterSpec getParameterSpec()
    {
        return SDitHParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SDitHPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        byte[] enc = (byte[])in.readObject();
        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(this.getEncoded());
    }
}
