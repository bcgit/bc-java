package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.util.Arrays;

/**
 * Key spec for rebuilding a user's SM9 signature private key (ds_A, GM/T 0044.2)
 * from its PKCS#8 encoding through {@code KeyFactory.SM9}. The encoding alone does
 * not determine a usable key - the signer also needs the signature master public
 * key and the identity, neither of which is part of it - so the spec carries all
 * three, letting a stored user key be reconstituted without access to the master
 * private key.
 * <p>
 * This extends {@link EncodedKeySpec} rather than {@link java.security.spec.PKCS8EncodedKeySpec}:
 * the encoded bytes are a real PKCS#8 encoding (reflected in {@link #getFormat()}), but the
 * spec is not self-sufficient the way a plain PKCS8EncodedKeySpec is meant to be, and
 * subclassing the concrete JDK type would let generic code treat it as one.
 * <p>
 * The matching spec is returned by the factory's {@code getKeySpec} method, so a
 * user key round-trips: store {@code getEncoded()} (or ask for this spec), rebuild
 * with {@code generatePrivate}. The verification side needs no spec - a user's
 * public key is derived from the master public key and the identity via
 * {@link SM9SigMasterPublicKey#getUserPublicKey(byte[])}.
 */
public class SM9SigUserPrivateKeySpec
    extends EncodedKeySpec
{
    private final SM9SigMasterPublicKey masterPublicKey;
    private final byte[] identity;

    /**
     * @param pkcs8Encoding   the user private key's PKCS#8 encoding, as returned by
     *                        the key's {@code getEncoded()}.
     * @param masterPublicKey the signature master public key the user key was derived under.
     * @param identity        the user's identity.
     */
    public SM9SigUserPrivateKeySpec(byte[] pkcs8Encoding, SM9SigMasterPublicKey masterPublicKey, byte[] identity)
    {
        super(pkcs8Encoding);
        if (masterPublicKey == null)
        {
            throw new NullPointerException("masterPublicKey cannot be null");
        }
        if (identity == null)
        {
            throw new NullPointerException("identity cannot be null");
        }
        this.masterPublicKey = masterPublicKey;
        this.identity = Arrays.clone(identity);
    }

    public SM9SigMasterPublicKey getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }

    public String getFormat()
    {
        return "PKCS#8";
    }
}
