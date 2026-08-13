package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.jcajce.interfaces.SM9SigUserPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;

/**
 * JCA wrapper for a user's SM9 signature private key (ds_A, a point of G1),
 * used with an {@code SM9} {@link java.security.Signature} to sign.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}. {@link #getIdentity()} returns
 * the identity the key was derived for, so a caller need not track it separately.
 */
class BCSM9SigPrivateKey
    implements SM9SigUserPrivateKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SigPrivateKeyParameters keyParams;

    BCSM9SigPrivateKey(SM9SigPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9SigPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public String getAlgorithm()
    {
        return "SM9-SIGN";
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
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 user private key", e);
        }
    }

    @Override
    public byte[] getIdentity()
    {
        return keyParams.getIdentity();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9SigPrivateKey))
        {
            return false;
        }
        return Arrays.constantTimeAreEqual(getEncoded(), ((BCSM9SigPrivateKey)o).getEncoded());
    }

    public int hashCode()
    {
        // derive from the public master key, never the secret key point
        return Arrays.hashCode(keyParams.getMasterPublicKey().getEncoded());
    }

    /**
     * Destroy the underlying private point ds. After destruction {@link #isDestroyed()}
     * returns true, {@link #getEncoded()} throws {@link IllegalStateException} and the
     * key can no longer sign.
     */
    public synchronized void destroy()
    {
        keyParams.destroy();
    }

    public boolean isDestroyed()
    {
        return keyParams.isDestroyed();
    }

    private Object writeReplace()
        throws java.io.ObjectStreamException
    {
        throw new java.io.NotSerializableException(
            "SM9 user identity keys are not serializable standalone; re-derive from the master key via generateUserKeyPair");
    }
}
