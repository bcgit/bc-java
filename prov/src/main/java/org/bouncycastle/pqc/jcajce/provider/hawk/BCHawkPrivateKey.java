package org.bouncycastle.pqc.jcajce.provider.hawk;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.HawkKey;
import org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * JCA private key wrapper for Hawk. Round-trips through PKCS#8
 * {@link PrivateKeyInfo} via the lightweight {@code PrivateKeyFactory}.
 * Equality uses {@link Arrays#constantTimeAreEqual} on the encoded private
 * key bytes to avoid leaking secret material through timing-distinguishable
 * comparisons.
 */
public class BCHawkPrivateKey
    implements PrivateKey, HawkKey
{
    private static final long serialVersionUID = 1L;

    private transient HawkPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCHawkPrivateKey(
        HawkPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCHawkPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (HawkPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCHawkPrivateKey)
        {
            BCHawkPrivateKey otherKey = (BCHawkPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        // Hawk private keys do not embed the full public key and keygen is not exposed for reconstruction.
        return getAlgorithm().hashCode();
    }

    /**
     * @return name of the algorithm - upper-case form of the Hawk parameter-set name
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

    public HawkParameterSpec getParameterSpec()
    {
        return HawkParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    HawkPrivateKeyParameters getKeyParams()
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
