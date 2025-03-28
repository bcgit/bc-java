package org.bouncycastle.bcpg;

import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

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

    public KeyIdentifier(String hexEncoded)
    {
        this(Hex.decode(hexEncoded));
    }

    /**
     * Create a new {@link KeyIdentifier} based on a keys fingerprint.
     * For fingerprints matching the format of a v4, v5 or v6 key, the constructor will
     * try to derive the corresponding key-id from the fingerprint.
     *
     * @param fingerprint fingerprint
     */
    public KeyIdentifier(byte[] fingerprint)
    {
        // Long KeyID
        if (fingerprint.length == 8)
        {
            keyId = FingerprintUtil.longFromRightMostBytes(fingerprint);
            this.fingerprint = null;
            return;
        }

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
        if (keyId == 0L)
        {
            this.keyId = 0L;
            this.fingerprint = new byte[0];
        }
        else
        {
            this.keyId = keyId;
            this.fingerprint = null;
        }
    }

    /**
     * Create a wildcard {@link KeyIdentifier}.
     */
    private KeyIdentifier()
    {
        this(0L);
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
        return Arrays.clone(fingerprint);
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
     * Returns true, if the {@link KeyIdentifier} specifies a wildcard (matches anything).
     * This is for example used with anonymous recipient key-ids / fingerprints, where the recipient
     * needs to try all available keys to decrypt the message.
     *
     * @return is wildcard
     */
    public boolean isWildcard()
    {
        return keyId == 0L && (fingerprint == null || fingerprint.length == 0);
    }

    /**
     * Return true if the KeyIdentifier has a fingerprint corresponding to the passed in one.
     *
     * @param fingerprint the fingerprint to match against.
     * @return true if there's a match, false otherwise.
     */
    public boolean hasFingerprint(byte[] fingerprint)
    {
        return Arrays.constantTimeAreEqual(this.fingerprint, fingerprint);
    }

    /**
     * Return true, if this {@link KeyIdentifier} matches the given other {@link KeyIdentifier}.
     * This will return true if the fingerprint matches, or if the key-id matches,
     * or if {@link #isWildcard()} returns true.
     *
     * @param other the identifier we are matching against.
     * @return true if we match other, false otherwise.
     */
    public boolean matches(KeyIdentifier other)
    {
        if (isWildcard() || other.isWildcard())
        {
            return true;
        }

        if (fingerprint != null && other.fingerprint != null)
        {
            return Arrays.constantTimeAreEqual(fingerprint, other.fingerprint);
        }
        else
        {
            return keyId == other.keyId;
        }
    }

    public static boolean matches(List<KeyIdentifier> identifiers, KeyIdentifier identifier, boolean explicit)
    {
        for (Iterator it = identifiers.iterator(); it.hasNext();)
        {
            KeyIdentifier candidate = (KeyIdentifier)it.next();
            
            if (!explicit && candidate.isWildcard())
            {
                return true;
            }

            if (candidate.getFingerprint() != null &&
                    Arrays.constantTimeAreEqual(candidate.getFingerprint(), identifier.getFingerprint()))
            {
                return true;
            }

            return candidate.getKeyId() == identifier.getKeyId();
        }
        return false;
    }

    /**
     * Return true, if this {@link KeyIdentifier} is present in the given list of {@link KeyIdentifier} .
     * This will return true if a fingerprint matches, or if a key-id matches,
     * or if {@link #isWildcard()} returns true.
     *
     * @param others the list of key identifiers to check.
     * @return true, if the identifier is present in the list, false otherwise.
     */
    public boolean isPresentIn(List<KeyIdentifier> others)
    {
        for (Iterator it = others.iterator(); it.hasNext();)
        {
            if (this.matches((KeyIdentifier)it.next()))
            {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof KeyIdentifier))
        {
            return false;
        }
        KeyIdentifier other = (KeyIdentifier) obj;
        if (getFingerprint() != null && other.getFingerprint() != null)
        {
            return Arrays.constantTimeAreEqual(getFingerprint(), other.getFingerprint());
        }
        return getKeyId() == other.getKeyId();
    }

    @Override
    public int hashCode()
    {
        return (int) getKeyId();
    }

    public String toString()
    {
        if (isWildcard())
        {
            return "*";
        }

        if (fingerprint == null)
        {
            return "" + keyId;
        }

        // -DM Hex.toHexString
        return Hex.toHexString(fingerprint).toUpperCase(Locale.getDefault());
    }

    public String toPrettyPrint()
    {
        if (isWildcard())
        {
            return "*";
        }
        if (fingerprint == null)
        {
            return "0x" + Long.toHexString(keyId).toUpperCase(Locale.getDefault());
        }
        return FingerprintUtil.prettifyFingerprint(fingerprint);
    }
}
