package org.bouncycastle.pqc.jcajce.provider.aimer;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.aimer.AIMerPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.AIMerKey;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCAIMerPublicKey
    implements PublicKey, AIMerKey
{
    private static final long serialVersionUID = 1L;

    private transient AIMerPublicKeyParameters params;

    public BCAIMerPublicKey(
        AIMerPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCAIMerPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (AIMerPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this AIMer public key with another object.
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

        if (o instanceof BCAIMerPublicKey)
        {
            BCAIMerPublicKey otherKey = (BCAIMerPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "AIMer-[128|192|256][f|s]"
     */
    public final String getAlgorithm()
    {
        return Strings.toUpperCase(params.getParameters().getName());
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

    public AIMerParameterSpec getParameterSpec()
    {
        return AIMerParameterSpec.fromName(params.getParameters().getName());
    }

    AIMerPublicKeyParameters getKeyParams()
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

