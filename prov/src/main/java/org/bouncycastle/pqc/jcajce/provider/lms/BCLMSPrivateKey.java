package org.bouncycastle.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCLMSPrivateKey
    implements PrivateKey, LMSPrivateKey
{
    private static final long serialVersionUID = 8568701712864512338L;

    private transient LMSKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCLMSPrivateKey(
        LMSKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCLMSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (LMSKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public long getIndex()
    {
        if (getUsagesRemaining() == 0)
        {
            throw new IllegalStateException("key exhausted");
        }

        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)keyParams).getIndex();
        }
        return ((HSSPrivateKeyParameters)keyParams).getIndex();
    }

    public long getUsagesRemaining()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)keyParams).getUsagesRemaining();
        }
        return ((HSSPrivateKeyParameters)keyParams).getUsagesRemaining();
    }

    public LMSPrivateKey extractKeyShard(int usageCount)
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return new BCLMSPrivateKey(((LMSPrivateKeyParameters)keyParams).extractKeyShard(usageCount));
        }
        return new BCLMSPrivateKey(((HSSPrivateKeyParameters)keyParams).extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "LMS";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCLMSPrivateKey)
        {
            BCLMSPrivateKey otherKey = (BCLMSPrivateKey)o;

            try
            {
                return Arrays.areEqual(keyParams.getEncoded(), otherKey.keyParams.getEncoded());
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to perform equals");     // should never happen.
            }
        }

        return false;
    }

    public int hashCode()
    {
        try
        {
            return Arrays.hashCode(keyParams.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to calculate hashCode");     // should never happen.
        }
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public int getLevels()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return 1;
        }
        else
        {
            return ((HSSPrivateKeyParameters)keyParams).getL();
        }
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
