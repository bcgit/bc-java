package org.bouncycastle.pqc.jcajce.provider.haetae;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.HaetaeKey;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * JCA private key wrapper for HAETAE. Round-trips through PKCS#8
 * {@link PrivateKeyInfo} via the lightweight {@code PrivateKeyFactory}.
 * Equality uses {@link Arrays#constantTimeAreEqual} on the encoded private
 * key bytes to avoid leaking secret material through timing-distinguishable
 * comparisons.
 */
public class BCHaetaePrivateKey
    implements PrivateKey, HaetaeKey
{
    private static final long serialVersionUID = 1L;

    private transient HAETAEPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCHaetaePrivateKey(
        HAETAEPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCHaetaePrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (HAETAEPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCHaetaePrivateKey)
        {
            BCHaetaePrivateKey otherKey = (BCHaetaePrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCHaetaePublicKey getPublicKey()
    {
        byte[] pk = Arrays.copyOfRange(params.getSeedSk(), 0, params.getParameters().getPublicKeyBytes());
        return new BCHaetaePublicKey(new HAETAEPublicKeyParameters(params.getParameters(), pk));
    }

    /**
     * @return name of the algorithm - upper-case form of the HAETAE parameter-set name
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

    public HaetaeParameterSpec getParameterSpec()
    {
        return HaetaeParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    HAETAEPrivateKeyParameters getKeyParams()
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
