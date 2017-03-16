package org.bouncycastle.openpgp.wot.key;

import static java.util.Arrays.*;
import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.Serializable;
import java.lang.ref.WeakReference;
import java.util.Arrays;

/**
 * An OpenPGP key's fingerprint.
 */
public class PgpKeyFingerprint implements Comparable<PgpKeyFingerprint>, Serializable
{
    private static final long serialVersionUID = 1L;

    private final byte[] fingerprint;
    private transient volatile int hashCode;
    private transient volatile WeakReference<String> toString;
    private transient volatile WeakReference<String> toHumanString;

    public PgpKeyFingerprint(final byte[] fingerprint)
    {
        assertNotNull("fingerprint", fingerprint);
        // In order to guarantee that this instance is immutable, we must copy the input.
        this.fingerprint = copyOf(fingerprint, fingerprint.length);
    }

    public PgpKeyFingerprint(final String fingerprint)
    {
        assertNotNull("fingerprint", fingerprint);
        this.fingerprint = decodeHexStr(fingerprint);
    }

    public byte[] getBytes()
    {
        // In order to guarantee that this instance stays immutable, we copy the byte array.
        return copyOf(fingerprint, fingerprint.length);
    }

    @Override
    public int hashCode()
    {
        if (hashCode == 0)
            hashCode = Arrays.hashCode(fingerprint);

        return hashCode;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;

        final PgpKeyFingerprint other = (PgpKeyFingerprint) obj;
        return Arrays.equals(fingerprint, other.fingerprint);
    }

    @Override
    public int compareTo(PgpKeyFingerprint o)
    {
        int res = Integer.compare(this.fingerprint.length, o.fingerprint.length);
        if (res != 0)
            return res;

        for (int i = 0; i < this.fingerprint.length; i++)
        {
            res = Byte.compare(this.fingerprint[i], o.fingerprint[i]);
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
            s = encodeHexStr(fingerprint);
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
}
