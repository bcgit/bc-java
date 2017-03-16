package org.bouncycastle.openpgp.wot.key;

import static java.util.Arrays.*;
import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.Serializable;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;

/**
 * Hash used as identifier of a user-identity or user-attribute.
 * <p>
 * Use {@link #createFromUserId(String)} or {@link #createFromUserAttribute(PGPUserAttributeSubpacketVector)} to create
 * an instance.
 */
public class PgpUserIdNameHash implements Comparable<PgpUserIdNameHash>, Serializable
{
    private static final long serialVersionUID = 1L;

    private final byte[] namehash;
    private transient volatile int hashCode;
    private transient volatile WeakReference<String> toString;
    private transient volatile WeakReference<String> toHumanString;

    protected PgpUserIdNameHash(final byte[] namehash)
    {
        assertNotNull("namehash", namehash);
        this.namehash = namehash;
    }

    public PgpUserIdNameHash(final String namehash)
    {
        assertNotNull("namehash", namehash);
        this.namehash = decodeHexStr(namehash);
    }

    public byte[] getBytes()
    {
        // In order to guarantee that this instance stays immutable, we copy the byte array.
        return copyOf(namehash, namehash.length);
    }

    @Override
    public int hashCode()
    {
        if (hashCode == 0)
            hashCode = Arrays.hashCode(namehash);

        return hashCode;
    }

    public boolean equals(final byte[] namehash)
    {
        if (namehash == null)
            return false;

        return Arrays.equals(this.namehash, namehash);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof byte[])
            return equals((byte[]) obj);

        if (getClass() != obj.getClass())
            return false;

        final PgpUserIdNameHash other = (PgpUserIdNameHash) obj;
        return Arrays.equals(namehash, other.namehash);
    }

    @Override
    public int compareTo(PgpUserIdNameHash o)
    {
        int res = Integer.compare(this.namehash.length, o.namehash.length);
        if (res != 0)
            return res;

        for (int i = 0; i < this.namehash.length; i++)
        {
            res = Byte.compare(this.namehash[i], o.namehash[i]);
            if (res != 0)
                return res;
        }
        return 0;
    }

    @Override
    public String toString()
    {
        String s = toString == null ? null : toString.get();
        if (s == null)
        {
            s = encodeHexStr(namehash);
            toString = new WeakReference<String>(s);
        }
        return s;
    }

    public String toHumanString()
    {
        String s = toHumanString == null ? null : toHumanString.get();
        if (s == null)
        {
            s = _toHumanString();
            toHumanString = new WeakReference<String>(s);
        }
        return s;
    }

    private String _toHumanString()
    {
        final StringBuilder sb = new StringBuilder();
        final String string = toString();

        for (int i = 0; i < string.length(); ++i)
        {
            if (i > 0 && (i % 4 == 0))
                sb.append(' ');

            sb.append(string.charAt(i));
        }
        return sb.toString();
    }

    /**
     * Creates an instance of {@code PgpUserIdNameHash} for the given user-identity.
     *
     * @param userId
     *            the user-identity for which to create a name-hash instance. Must not be <code>null</code>.
     * @return the name-hash. Never <code>null</code>.
     */
    public static PgpUserIdNameHash createFromUserId(final String userId)
    {
        assertNotNull("userId", userId);

        final RIPEMD160Digest digest = new RIPEMD160Digest();
        byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8); // TODO is this correct?! really UTF-8?! check
                                                                      // with my own name! ;-)
        digest.update(userIdBytes, 0, userIdBytes.length);
        final byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);

        return new PgpUserIdNameHash(out);
    }

    /**
     * Creates an instance of {@code PgpUserIdNameHash} for the given user-attribute. A user-attribute usually is an
     * image.
     *
     * @param userAttribute
     *            the user-attribute for which to create a name-hash instance. Must not be <code>null</code>.
     * @return the name-hash. Never <code>null</code>.
     */
    public static PgpUserIdNameHash createFromUserAttribute(final PGPUserAttributeSubpacketVector userAttribute)
    {
        assertNotNull("userAttribute", userAttribute);

        final RIPEMD160Digest digest = new RIPEMD160Digest();

        // TODO this needs to be extended, if there is ever any other attribute type (other than image) possible, too!
        // Currently, image seems to be the only supported attribute. Alternatively, we could get the data via
        // reflection...
        final UserAttributeSubpacket subpacket = userAttribute.getSubpacket(UserAttributeSubpacketTags.IMAGE_ATTRIBUTE);
        assertNotNull("subpacket", subpacket);
        final byte[] data = assertNotNull("subpacket.data", subpacket.getData());
        digest.update(data, 0, data.length);

        final byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return new PgpUserIdNameHash(out);
    }
}
