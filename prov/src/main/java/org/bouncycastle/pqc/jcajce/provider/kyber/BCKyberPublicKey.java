package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.interfaces.KyberPublicKey;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCKyberPublicKey
    implements KyberPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient MLKEMPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCKyberPublicKey(
        MLKEMPublicKeyParameters params)
    {
        init(params);
    }

    public BCKyberPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init((MLKEMPublicKeyParameters)PublicKeyFactory.createKey(keyInfo));
    }

    private void init(MLKEMPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Kyber public key with another object.
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

        if (o instanceof BCKyberPublicKey)
        {
            BCKyberPublicKey otherKey = (BCKyberPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "KYBER512, KYBER768, etc..."
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

    public KyberParameterSpec getParameterSpec()
    {
        return KyberParameterSpec.fromName(params.getParameters().getName());
    }

    MLKEMPublicKeyParameters getKeyParams()
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
