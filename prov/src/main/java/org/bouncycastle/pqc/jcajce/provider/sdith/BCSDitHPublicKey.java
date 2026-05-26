package org.bouncycastle.pqc.jcajce.provider.sdith;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.sdith.SDitHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SDitHKey;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCSDitHPublicKey
    implements PublicKey, SDitHKey
{
    private static final long serialVersionUID = 1L;

    private transient SDitHPublicKeyParameters params;

    public BCSDitHPublicKey(SDitHPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCSDitHPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (SDitHPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCSDitHPublicKey)
        {
            BCSDitHPublicKey otherKey = (BCSDitHPublicKey)o;
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

    public SDitHParameterSpec getParameterSpec()
    {
        return SDitHParameterSpec.fromName(params.getParameters().getName());
    }

    SDitHPublicKeyParameters getKeyParams()
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
