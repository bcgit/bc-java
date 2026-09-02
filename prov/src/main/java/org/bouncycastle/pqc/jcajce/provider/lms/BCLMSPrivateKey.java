package org.bouncycastle.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;

public class BCLMSPrivateKey
    implements LMSPrivateKey
{
    private static final long serialVersionUID = 8568701712864512338L;

    private transient HSSPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCLMSPrivateKey(LMSKeyParameters keyParams)
    {
        if (keyParams instanceof HSSPrivateKeyParameters)
        {
            this.keyParams = (HSSPrivateKeyParameters)keyParams;
        }
        else
        {
            LMSPrivateKeyParameters lms = (LMSPrivateKeyParameters)keyParams;
            this.keyParams = new HSSPrivateKeyParameters(lms, lms.getIndex(), lms.getIndex() + lms.getUsagesRemaining());
        }
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
        this.keyParams = (HSSPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public long getIndex()
    {
        // both reads under the key's own monitor, so a signature in between cannot split them
        synchronized (keyParams)
        {
            if (keyParams.getUsagesRemaining() == 0)
            {
                throw new IllegalStateException("key exhausted");
            }

            return keyParams.getIndex();
        }
    }

    public long getUsagesRemaining()
    {
        return keyParams.getUsagesRemaining();
    }

    public LMSPrivateKey extractKeyShard(int usageCount)
    {
        return new BCLMSPrivateKey(keyParams.extractKeyShard(usageCount));
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
            return keyParams.equals(((BCLMSPrivateKey)o).keyParams);
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.hashCode();
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public int getLevels()
    {
        return keyParams.getL();
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
