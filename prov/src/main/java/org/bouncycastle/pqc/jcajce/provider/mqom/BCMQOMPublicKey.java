package org.bouncycastle.pqc.jcajce.provider.mqom;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.mqom.MQOMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.MQOMKey;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCMQOMPublicKey
    implements PublicKey, MQOMKey
{
    private static final long serialVersionUID = 1L;

    private transient MQOMPublicKeyParameters params;

    public BCMQOMPublicKey(MQOMPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCMQOMPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (MQOMPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCMQOMPublicKey)
        {
            BCMQOMPublicKey other = (BCMQOMPublicKey)o;
            return Arrays.areEqual(params.getEncoded(), other.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

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

    public MQOMParameterSpec getParameterSpec()
    {
        return MQOMParameterSpec.fromName(params.getParameters().getName());
    }

    MQOMPublicKeyParameters getKeyParams()
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
