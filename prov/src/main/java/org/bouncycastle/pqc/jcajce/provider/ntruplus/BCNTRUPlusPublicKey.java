package org.bouncycastle.pqc.jcajce.provider.ntruplus;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUPlusPublicKey;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCNTRUPlusPublicKey
    implements NTRUPlusPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient NTRUPlusPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCNTRUPlusPublicKey(
        NTRUPlusPublicKeyParameters params)
    {
        init(params);
    }

    public BCNTRUPlusPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init((NTRUPlusPublicKeyParameters)PublicKeyFactory.createKey(keyInfo));
    }
    private void init(NTRUPlusPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }


    /**
     * Compare this NTRUPlus public key with another object.
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

        if (o instanceof BCNTRUPlusPublicKey)
        {
            BCNTRUPlusPublicKey otherKey = (BCNTRUPlusPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
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
            encoding = KeyUtil.getEncodedSubjectPublicKeyInfo(params);
        }

        return Arrays.clone(encoding);
    }

    public String getFormat()
    {
        return "X.509";
    }

    public NTRUPlusParameterSpec getParameterSpec()
    {
        return NTRUPlusParameterSpec.fromName(params.getParameters().getName());
    }

    NTRUPlusPublicKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}

