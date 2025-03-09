package org.bouncycastle.pqc.jcajce.provider.mayo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.mayo.MayoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.MayoKey;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCMayoPrivateKey
    implements PrivateKey, MayoKey
{
    private static final long serialVersionUID = 1L;

    private transient MayoPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCMayoPrivateKey(
        MayoPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCMayoPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (MayoPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
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

        if (o instanceof BCMayoPrivateKey)
        {
            BCMayoPrivateKey otherKey = (BCMayoPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "Mayo[1|2|3|5]"
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

    public MayoParameterSpec getParameterSpec()
    {
        return MayoParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    MayoPrivateKeyParameters getKeyParams()
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

