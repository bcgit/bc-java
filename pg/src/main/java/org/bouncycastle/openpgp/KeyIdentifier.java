package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.util.List;

/**
 * Utility class for matching key-ids / fingerprints.
 * A {@link KeyIdentifier} can be created from either a 64-bit key-id, a fingerprint, or both.
 * This class was created to enable a seamless transition from use of key-ids in the API
 * towards identifying keys via fingerprints.
 */
public class KeyIdentifier
{
    private final byte[] fingerprint;
    private final long keyId;

    /**
     * Create a new {@link KeyIdentifier} based on a keys fingerprint.
     * For fingerprints matching the format of a v4, v5 or v6 key, the constructor will
     * try to derive the corresponding key-id from the fingerprint.
     *
     * @param fingerprint fingerprint
     */
    public KeyIdentifier(byte[] fingerprint)
    {
        this.fingerprint = Arrays.clone(fingerprint);

        // v4
        if (fingerprint.length == 20)
        {
            keyId = FingerprintUtil.keyIdFromV4Fingerprint(fingerprint);
        }
        // v5, v6
        else if (fingerprint.length == 32)
        {
            keyId = FingerprintUtil.keyIdFromV6Fingerprint(fingerprint);
        }
        else
        {
            keyId = 0L;
        }
    }

    /**
     * Create a {@link KeyIdentifier} based on the given fingerprint and key-id.
     *
     * @param fingerprint fingerprint
     * @param keyId key-id
     */
    public KeyIdentifier(byte[] fingerprint, long keyId)
    {
        this.fingerprint = Arrays.clone(fingerprint);
        this.keyId = keyId;
    }

    /**
     * Create a {@link KeyIdentifier} based on the given key-id.
     * {@code fingerprint} will be set to {@code null}.
     *
     * @param keyId key-id
     */
    public KeyIdentifier(long keyId)
    {
        this(null, keyId);
    }

    /**
     * Create a {@link KeyIdentifier} for the given {@link PGPPublicKey}.
     *
     * @param key key
     */
    public KeyIdentifier(PGPPublicKey key)
    {
        this(key.getFingerprint(), key.getKeyID());
    }

    /**
     * Create a {@link KeyIdentifier} for the given {@link PGPSecretKey}.
     *
     * @param key key
     */
    public KeyIdentifier(PGPSecretKey key)
    {
        this(key.getPublicKey());
    }

    /**
     * Create a {@link KeyIdentifier} for the given {@link PGPPrivateKey}.
     *
     * @param key key
     * @param fingerprintCalculator calculate the fingerprint
     * @throws PGPException if an exception happens while calculating the fingerprint
     */
    public KeyIdentifier(PGPPrivateKey key, KeyFingerPrintCalculator fingerprintCalculator)
            throws PGPException
    {
        this(new PGPPublicKey(key.getPublicKeyPacket(), fingerprintCalculator));
    }

    /**
     * Create a wildcard {@link KeyIdentifier}.
     */
    private KeyIdentifier()
    {
        this(new byte[0], 0L);
    }

    /**
     * Create a wildcard {@link KeyIdentifier}.
     *
     * @return wildcard key identifier
     */
    public static KeyIdentifier wildcard()
    {
        return new KeyIdentifier();
    }

    /**
     * Return the fingerprint of the {@link KeyIdentifier}.
     * {@code fingerprint} might be null, if the {@link KeyIdentifier} was created from just a key-id.
     * If {@link #isWildcard()} returns true, this method returns an empty, but non-null array.
     *
     * @return fingerprint
     */
    public byte[] getFingerprint()
    {
        return fingerprint;
    }

    /**
     * Return the key-id of the {@link KeyIdentifier}.
     * This might be {@code 0L} if {@link #isWildcard()} returns true, or if an unknown
     * fingerprint was passed in.
     *
     * @return key-id
     */
    public long getKeyId()
    {
        return keyId;
    }

    /**
     * Return true, if this {@link KeyIdentifier} matches the given {@link PGPPublicKey}.
     * This will return true if the fingerprint matches, or if the key-id matches,
     * or if {@link #isWildcard()} returns true.
     *
     * @param key key
     * @return if the identifier matches the key
     */
    public boolean matches(PGPPublicKey key)
    {
        if (isWildcard())
        {
            return true;
        }

        if (fingerprint != null)
        {
            return Arrays.constantTimeAreEqual(fingerprint, key.getFingerprint());
        }
        else
        {
            return keyId == key.getKeyID();
        }
    }

    /**
     * Return true if this {@link KeyIdentifier} matches the given {@link PGPSecretKey}.
     * This will return true if the fingerprint matches, or if the key-id matches,
     * or if {@link #isWildcard()} returns true.
     *
     * @param key key
     * @return whether the identifier matches the key
     */
    public boolean matches(PGPSecretKey key)
    {
        return matches(key.getPublicKey());
    }

    /**
     * Return true if this {@link KeyIdentifier} matches the given {@link PGPPrivateKey}.
     * This will return true if the fingerprint matches, or if the key-id matches,
     * or in case that {@link #isWildcard()} is true.
     *
     * @param key key
     * @param fingerprintCalculator to calculate the fingerprint
     * @return whether the identifier matches the key
     * @throws PGPException if an exception happens while calculating the fingerprint
     */
    public boolean matches(PGPPrivateKey key,
                           KeyFingerPrintCalculator fingerprintCalculator)
            throws PGPException
    {
        return matches(new PGPPublicKey(key.getPublicKeyPacket(), fingerprintCalculator));
    }

    public boolean matches(PGPSignature sig)
    {
        if (isWildcard())
        {
            return true;
        }

        PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
        PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();

        return matches(hashed) || matches(unhashed);
    }

    private boolean matches(PGPSignatureSubpacketVector subpackets)
    {
        if (fingerprint != null)
        {
            for (SignatureSubpacket subpacket : subpackets.getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT))
            {
                IssuerFingerprint issuer = (IssuerFingerprint) subpacket;
                if (Arrays.constantTimeAreEqual(fingerprint, issuer.getFingerprint()))
                {
                    return true;
                }
                // wildcard fingerprint
                if (issuer.getFingerprint().length == 0)
                {
                    return true;
                }
            }
        }

        for (SignatureSubpacket subpacket : subpackets.getSubpackets(SignatureSubpacketTags.ISSUER_KEY_ID))
        {
            IssuerKeyID issuer = (IssuerKeyID) subpacket;
            if (issuer.getKeyID() == keyId)
            {
                return true;
            }
            // wildcard key-id
            if (issuer.getKeyID() == 0)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true, if the {@link KeyIdentifier} specifies a wildcard (matches anything).
     * This is for example used with anonymous recipient key-ids / fingerprints, where the recipient
     * needs to try all available keys to decrypt the message.
     *
     * @return is wildcard
     */
    public boolean isWildcard()
    {
        return keyId == 0L && fingerprint.length == 0;
    }

    /**
     * Return true, if any of the {@link KeyIdentifier KeyIdentifiers} in the {@code identifiers} list
     * matches the given {@link PGPPublicKey}.
     *
     * @param identifiers list of identifiers
     * @param key key
     * @return true if any matches, false if none matches
     */
    public static boolean matches(List<KeyIdentifier> identifiers, PGPPublicKey key)
    {
        for (KeyIdentifier identifier : identifiers)
        {
            if (identifier.matches(key))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Return true, if any of the {@link KeyIdentifier KeyIdentifiers} in the {@code identifiers} list
     * matches the given {@link PGPSecretKey}.
     *
     * @param identifiers list of identifiers
     * @param key key
     * @return true if any matches, false if none matches
     */
    public static boolean matches(List<KeyIdentifier> identifiers, PGPSecretKey key)
    {
        for (KeyIdentifier identifier : identifiers)
        {
            if (identifier.matches(key))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Return true, if any of the {@link KeyIdentifier KeyIdentifiers} in the {@code identifiers} list
     * matches the given {@link PGPPrivateKey}.
     *
     * @param identifiers list of identifiers
     * @param key key
     * @param fingerprintCalculator to calculate the fingerprint
     * @return true if any matches, false if none matches
     */
    public static boolean matches(List<KeyIdentifier> identifiers,
                                  PGPPrivateKey key,
                                  KeyFingerPrintCalculator fingerprintCalculator)
            throws PGPException
    {
        for (KeyIdentifier identifier : identifiers)
        {
            if (identifier.matches(key, fingerprintCalculator))
            {
                return true;
            }
        }
        return false;
    }

    public String toString()
    {
        if (isWildcard())
        {
            return "*";
        }

        if (getFingerprint() == null)
        {
            return "" + keyId;
        }

        // -DM Hex.toHexString
        return Hex.toHexString(fingerprint).toUpperCase();
    }
}
