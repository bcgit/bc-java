package org.bouncycastle.pqc.jcajce.provider.faest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.NamedParameterSpecUtil;
import org.bouncycastle.pqc.crypto.faest.FaestPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.FaestKey;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCFaestPrivateKey
    implements PrivateKey, FaestKey
{
    private static final long serialVersionUID = 1L;

    private transient FaestPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCFaestPrivateKey(
        FaestPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCFaestPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (FaestPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCFaestPrivateKey)
        {
            BCFaestPrivateKey otherKey = (BCFaestPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        // FAEST public OWF output requires package-private Faest.owf to recompute from the secret key.
        return getAlgorithm().hashCode();
    }

    /**
     * @return name of the algorithm - upper-case form of the FAEST parameter-set name
     */
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

    public FaestParameterSpec getParameterSpec()
    {
        return FaestParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    FaestPrivateKeyParameters getKeyParams()
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
