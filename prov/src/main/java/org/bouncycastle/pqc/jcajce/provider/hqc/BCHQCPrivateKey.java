package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.HQCKey;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCHQCPrivateKey
    implements PrivateKey, HQCKey
{
    private static final long serialVersionUID = 1L;

    private transient HQCPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCHQCPrivateKey(
            HQCPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCHQCPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (HQCPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCHQCPrivateKey)
        {
            BCHQCPrivateKey otherKey = (BCHQCPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "HQC"
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

    public HQCParameterSpec getParameterSpec()
    {
        return HQCParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    HQCPrivateKeyParameters getKeyParams()
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
