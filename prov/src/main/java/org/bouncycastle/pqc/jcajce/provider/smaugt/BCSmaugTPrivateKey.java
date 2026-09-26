package org.bouncycastle.pqc.jcajce.provider.smaugt;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.NamedParameterSpecUtil;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SmaugTKey;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCSmaugTPrivateKey
    implements PrivateKey, SmaugTKey
{
    private static final long serialVersionUID = 1L;

    private transient SmaugTPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSmaugTPrivateKey(
        SmaugTPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSmaugTPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SmaugTPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCSmaugTPrivateKey)
        {
            BCSmaugTPrivateKey otherKey = (BCSmaugTPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        // Derived from the parameter set, never from the secret private encoding: a hashCode()
        // folding in the secret leaks a hash of it to anything that puts the key in a HashMap.
        // SMAUG-T private keys carry no separately accessible public component, so - as with
        // BIKE - the algorithm name is what is left. Same-parameter-set keys therefore collide,
        // which is legal and keeps equals()-equal keys hashing equal.
        return getAlgorithm().hashCode();
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

    public SmaugTParameterSpec getParameterSpec()
    {
        return SmaugTParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SmaugTPrivateKeyParameters getKeyParams()
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
