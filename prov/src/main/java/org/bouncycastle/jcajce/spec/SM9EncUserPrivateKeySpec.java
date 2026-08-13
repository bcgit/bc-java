package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.util.Arrays;

/**
 * Key spec for rebuilding a user's SM9 encryption (KEM / decryption) private key
 * (de, GM/T 0044.4) from its PKCS#8 encoding through {@code KeyFactory.SM9}. The
 * encoding alone does not determine a usable key - decryption also needs the
 * encryption master public key, the user's identity (part of the decryption KDF
 * input) and the hid the KGC derived the key under, none of which are part of it -
 * so the spec carries all four, letting a stored user key be reconstituted without
 * access to the master private key.
 * <p>
 * This extends {@link EncodedKeySpec} rather than {@link java.security.spec.PKCS8EncodedKeySpec}:
 * the encoded bytes are a real PKCS#8 encoding (reflected in {@link #getFormat()}), but the
 * spec is not self-sufficient the way a plain PKCS8EncodedKeySpec is meant to be, and
 * subclassing the concrete JDK type would let generic code treat it as one.
 * <p>
 * The matching spec is returned by the factory's {@code getKeySpec} method, so a
 * user key round-trips: store {@code getEncoded()} (or ask for this spec), rebuild
 * with {@code generatePrivate}. There is deliberately no key-exchange counterpart,
 * mirroring the lightweight API: an exchange user key is obtained from the master
 * key's derivation instead.
 */
public class SM9EncUserPrivateKeySpec
    extends EncodedKeySpec
{
    private final SM9EncMasterPublicKey masterPublicKey;
    private final byte[] identity;
    private final byte hid;

    /**
     * @param pkcs8Encoding   the user private key's PKCS#8 encoding, as returned by
     *                        the key's {@code getEncoded()}.
     * @param masterPublicKey the encryption master public key the user key was derived under.
     * @param identity        the user's identity.
     * @param hid             the private-key generation function identifier the KGC
     *                        derived the key under.
     */
    public SM9EncUserPrivateKeySpec(byte[] pkcs8Encoding, SM9EncMasterPublicKey masterPublicKey,
                                    byte[] identity, byte hid)
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
        this.hid = hid;
    }

    public SM9EncMasterPublicKey getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }

    /**
     * The private-key generation function identifier hid the key was derived
     * under - the KGC's published choice, not sensitive.
     */
    public byte getHid()
    {
        return hid;
    }

    public String getFormat()
    {
        return "PKCS#8";
    }
}
