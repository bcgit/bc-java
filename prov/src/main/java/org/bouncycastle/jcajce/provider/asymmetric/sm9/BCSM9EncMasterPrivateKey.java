package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectStreamException;
import java.security.KeyPair;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;

/**
 * JCA wrapper for an SM9 encryption master private key (ke), held by the KGC.
 * Use {@link #generateUserKeyPair(byte[])} (a KGC operation, hid = 0x03) to derive
 * a user's key pair, or {@link #extractPrivateKey(byte[])} for the private half alone.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9EncMasterPrivateKey
    implements SM9EncMasterPrivateKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncMasterPrivateKeyParameters keyParams;

    BCSM9EncMasterPrivateKey(SM9EncMasterPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    /**
     * Derive the decryption private key of the user identified by {@code id};
     * {@link #generateUserKeyPair(byte[])} returns the user's full key pair.
     */
    private BCSM9EncPrivateKey extractPrivateKey(byte[] id)
    {
        return new BCSM9EncPrivateKey(keyParams.generatePrivateKey(id));
    }

    /**
     * Generate the key pair of the user identified by {@code id}: the public key to
     * encapsulate to and the private key that decapsulates (a KGC operation, hid = 0x03).
     */
    public KeyPair generateUserKeyPair(byte[] id)
    {
        return new KeyPair(
            new BCSM9EncPublicKey(keyParams.getPublicKeyParameters().getUserPublicKey(id)),
            extractPrivateKey(id));
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
        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 encryption master private key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncMasterPrivateKey))
        {
            return false;
        }
        return Arrays.constantTimeAreEqual(getEncoded(), ((BCSM9EncMasterPrivateKey)o).getEncoded());
    }

    public int hashCode()
    {
        // derive from the public master key, never the secret ke
        return Arrays.hashCode(keyParams.getPublicKeyParameters().getEncoded());
    }

    /**
     * Destroy the underlying master secret ke. After destruction {@link #isDestroyed()}
     * returns true and the secret-bearing operations ({@link #getEncoded()},
     * {@link #generateUserKeyPair(byte[])}) throw {@link IllegalStateException};
     * user key pairs already generated are unaffected.
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
        throws ObjectStreamException
    {
        if (keyParams.isDestroyed())
        {
            throw new NotSerializableException("key destroyed");
        }
        return new SM9KeyProxy(true, getEncoded());
    }
}
