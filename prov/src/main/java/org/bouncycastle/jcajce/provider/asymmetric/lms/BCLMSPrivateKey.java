package org.bouncycastle.jcajce.provider.asymmetric.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.util.Exceptions;

public class BCLMSPrivateKey
    implements LMSPrivateKey, Destroyable
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

    public BCLMSPrivateKey extractKeyShard(int usageCount)
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
        if (keyParams.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

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

            // a destroyed key no longer exposes its value, so it is only equal to itself.
            if (isDestroyed() || otherKey.isDestroyed())
            {
                return false;
            }

            return keyParams.equals(otherKey.keyParams);
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

    /**
     * Destroy this key, zeroizing the secret key material it holds.
     * <p>
     * The master secret of every tree in the hierarchy is zeroized; the key identifiers, indexes,
     * chaining signatures and cached tree nodes are retained, so {@link #getIndex()},
     * {@link #getUsagesRemaining()} and {@link #getLevels()} keep working. After destruction
     * {@link #isDestroyed()} returns true, {@link #getEncoded()} and {@link #extractKeyShard(int)}
     * throw {@link IllegalStateException}, the key can no longer be serialized, and a Signature
     * refuses it at initSign. Shards extracted before destruction are independent copies and are
     * unaffected. As the underlying {@link HSSPrivateKeyParameters} object is destroyed, keys
     * sharing it are invalidated too.
     */
    public synchronized void destroy()
    {
        keyParams.destroy();
    }

    public boolean isDestroyed()
    {
        return keyParams.isDestroyed();
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

        try
        {
            out.writeObject(this.getEncoded());
        }
        catch (IllegalStateException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }
}
