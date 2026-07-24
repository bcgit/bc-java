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
import org.bouncycastle.crypto.params.SM9SignMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9SignMasterPrivateKey;

/**
 * JCA wrapper for an SM9 signature master private key (ks), held by the KGC.
 * Use {@link #generateUserKeyPair(byte[])} (a KGC operation, hid = 0x01) to derive
 * a user's key pair.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9SignMasterPrivateKey
    implements SM9SignMasterPrivateKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SignMasterPrivateKeyParameters keyParams;

    BCSM9SignMasterPrivateKey(SM9SignMasterPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9SignMasterPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    private BCSM9SignPrivateKey extractPrivateKey(byte[] id)
    {
        return new BCSM9SignPrivateKey(keyParams.generatePrivateKey(id));
    }

    /**
     * Generate the key pair of the user identified by {@code id}: the private key
     * that signs and the public key a verifier checks against (a KGC operation,
     * hid = 0x01).
     */
    public KeyPair generateUserKeyPair(byte[] id)
    {
        return new KeyPair(
            new BCSM9SignPublicKey(keyParams.getPublicKeyParameters(), id), extractPrivateKey(id));
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
        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 master private key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9SignMasterPrivateKey))
        {
            return false;
        }
        return Arrays.constantTimeAreEqual(getEncoded(), ((BCSM9SignMasterPrivateKey)o).getEncoded());
    }

    public int hashCode()
    {
        // derive from the public master key, never the secret ks
        return Arrays.hashCode(keyParams.getPublicKeyParameters().getEncoded());
    }

    /**
     * Destroy the underlying master secret ks. After destruction {@link #isDestroyed()}
     * returns true and the secret-bearing operations ({@link #getEncoded()},
     * {@link #generateUserKeyPair(byte[])}) throw {@link IllegalStateException};
     * user keys already derived are unaffected.
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
