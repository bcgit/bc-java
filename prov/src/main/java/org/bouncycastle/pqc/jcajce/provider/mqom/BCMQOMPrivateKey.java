package org.bouncycastle.pqc.jcajce.provider.mqom;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.MQOMKey;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCMQOMPrivateKey
    implements PrivateKey, MQOMKey
{
    private static final long serialVersionUID = 1L;

    private transient MQOMPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCMQOMPrivateKey(MQOMPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCMQOMPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (MQOMPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCMQOMPrivateKey)
        {
            BCMQOMPrivateKey other = (BCMQOMPrivateKey)o;
            return Arrays.constantTimeAreEqual(params.getEncoded(), other.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCMQOMPublicKey getPublicKey()
    {
        return new BCMQOMPublicKey(params.getPublicKeyParameters());
    }

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

    public MQOMParameterSpec getParameterSpec()
    {
        return MQOMParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    MQOMPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        byte[] enc = (byte[])in.readObject();
        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(this.getEncoded());
    }
}
