package org.bouncycastle.pqc.jcajce.provider.sqisign;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SQIsignKey;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCSQIsignPublicKey
    implements PublicKey, SQIsignKey
{
    private static final long serialVersionUID = 1L;

    private transient SQIsignPublicKeyParameters params;

    public BCSQIsignPublicKey(SQIsignPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCSQIsignPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (SQIsignPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCSQIsignPublicKey)
        {
            BCSQIsignPublicKey otherKey = (BCSQIsignPublicKey)o;
            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    public final String getAlgorithm()
    {
        return params.getParameters().getName();
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

    public SQIsignParameterSpec getParameterSpec()
    {
        return SQIsignParameterSpec.fromName(params.getParameters().getName());
    }

    SQIsignPublicKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        byte[] enc = (byte[])in.readObject();
        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(this.getEncoded());
    }
}
