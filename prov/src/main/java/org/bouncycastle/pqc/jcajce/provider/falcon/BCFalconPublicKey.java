package org.bouncycastle.pqc.jcajce.provider.falcon;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCFalconPublicKey
    implements FalconPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient FalconPublicKeyParameters params;

    public BCFalconPublicKey(
        FalconPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCFalconPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (FalconPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this Falcon public key with another object.
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

        if (o instanceof BCFalconPublicKey)
        {
            BCFalconPublicKey otherKey = (BCFalconPublicKey)o;

            return Arrays.areEqual(params.getH(), otherKey.params.getH());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getH());
    }

    /**
     * @return name of the algorithm - "Falcon"
     */
    public final String getAlgorithm()
    {
        return "Falcon";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public FalconParameterSpec getParameterSpec()
    {
        return FalconParameterSpec.fromName(params.getParameters().getName());
    }

    FalconPublicKeyParameters getKeyParams()
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
