package org.bouncycastle.pqc.jcajce.provider.sqisign;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SQIsignKey;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCSQIsignPrivateKey
    implements PrivateKey, SQIsignKey
{
    private static final long serialVersionUID = 1L;

    private transient SQIsignPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSQIsignPrivateKey(SQIsignPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSQIsignPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SQIsignPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCSQIsignPrivateKey)
        {
            BCSQIsignPrivateKey otherKey = (BCSQIsignPrivateKey)o;
            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getParameterSpec().hashCode();
    }

    public final String getAlgorithm()
    {
        return params.getParameters().getName();
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

    public SQIsignParameterSpec getParameterSpec()
    {
        return SQIsignParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SQIsignPrivateKeyParameters getKeyParams()
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
