package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey;

/**
 * JCA wrapper for a user's SM9 encryption (decryption) private key (de, a point
 * of G2), used with an SM9 {@link javax.crypto.Cipher} in DECRYPT_MODE. The
 * user's identity is carried within (it is part of the decryption KDF input) and
 * available via {@link #getIdentity()}, so a caller need not track it separately.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
class BCSM9EncPrivateKey
    implements SM9EncUserPrivateKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncPrivateKeyParameters keyParams;

    BCSM9EncPrivateKey(SM9EncPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9EncPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    @Override
    public byte[] getIdentity()
    {
        return keyParams.getIdentity();
    }

    public String getAlgorithm()
    {
        return "SM9-ENC";
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
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 user decryption key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncPrivateKey))
        {
            return false;
        }
        return Arrays.constantTimeAreEqual(getEncoded(), ((BCSM9EncPrivateKey)o).getEncoded());
    }

    public int hashCode()
    {
        // derive from the public master key, never the secret key point
        return Arrays.hashCode(keyParams.getMasterPublicKey().getEncoded());
    }

    /**
     * Destroy the underlying private point de (and the carried identity). After
     * destruction {@link #isDestroyed()} returns true, {@link #getEncoded()} throws
     * {@link IllegalStateException} and the key can no longer decapsulate/decrypt.
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
