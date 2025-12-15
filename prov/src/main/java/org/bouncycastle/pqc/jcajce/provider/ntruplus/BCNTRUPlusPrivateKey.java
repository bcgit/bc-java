package org.bouncycastle.pqc.jcajce.provider.ntruplus;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUPlusPublicKey;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCNTRUPlusPrivateKey
    implements NTRUPlusPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient NTRUPlusPrivateKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;
    private transient ASN1Set attributes;

    public BCNTRUPlusPrivateKey(
        NTRUPlusPrivateKeyParameters params)
    {
        init(params, null);
    }

    public BCNTRUPlusPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init((NTRUPlusPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo), keyInfo.getAttributes());
    }

    private void init(NTRUPlusPrivateKeyParameters params, ASN1Set attributes)
    {
        this.attributes = attributes;
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this NTRUPlus private key with another object.
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

        if (o instanceof BCNTRUPlusPrivateKey)
        {
            BCNTRUPlusPrivateKey otherKey = (BCNTRUPlusPrivateKey)o;

            return Arrays.areEqual(getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "FALCON-512 or FALCON-1024"
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            encoding = KeyUtil.getEncodedPrivateKeyInfo(params, attributes);
        }

        return Arrays.clone(encoding);
    }

    public NTRUPlusParameterSpec getParameterSpec()
    {
        return NTRUPlusParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    NTRUPlusPrivateKeyParameters getKeyParams()
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

