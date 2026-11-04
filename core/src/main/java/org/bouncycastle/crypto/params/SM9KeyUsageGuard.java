package org.bouncycastle.crypto.params;

import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * The record, kept in memory by this copy of the library, of which of the SM9 KEM and SM9 public-key
 * decryption each SM9 encryption user key has been used for - see
 * {@link SM9EncPrivateKeyParameters#recordUsage(int)}. The record is static state of this class, so
 * each class loader that loads its own copy of the library keeps a record of its own.
 * <p>
 * A key is recognised by its value rather than by its object, so the same key rebuilt as a new
 * object finds the record its earlier objects made. The value itself is not kept: a record is
 * found by an SM3 digest of the key's point and identity, which the point cannot be recovered from.
 * Taking the digest draws on no random source.
 * <p>
 * A record lives as long as any key object that has been checked against it and not destroyed since,
 * and the {@value #RECENT} records most recently checked are held besides, so that a key rebuilt for
 * each use is still recognised between its uses. Nothing else is held, however many keys pass through.
 */
final class SM9KeyUsageGuard
{
    /**
     * Whether a key may serve both functions when {@link Properties#SM9_ALLOW_MULTI_USE} is not
     * set - the default the property overrides either way.
     */
    private static final boolean ALLOW_MULTI_USE_DEFAULT = false;

    /**
     * How many of the most recently checked records are held beyond the key objects that hold them.
     * The javadoc of {@link SM9EncPrivateKeyParameters#recordUsage(int)} and the release notes give
     * this number.
     */
    static final int RECENT = 1024;

    // record -> WeakReference(record): each record is filed under itself, so its entry lasts exactly
    // as long as the record does
    private static final WeakHashMap records = new WeakHashMap();

    // the records most recently checked, in a ring through this sentinel, newest first: recent.next
    // is the newest and recent.prev the oldest. A ring of its own rather than an access-ordered
    // LinkedHashMap, which is Java 1.4 API, as this class is built for Java 1.3 as well
    private static final Record recent = new Record();
    private static int recentCount;

    private SM9KeyUsageGuard()
    {
    }

    /**
     * Whether the check applies to the calling thread now: it does unless
     * {@link Properties#SM9_ALLOW_MULTI_USE} is set.
     */
    static boolean isOn()
    {
        return !Properties.isOverrideSet(Properties.SM9_ALLOW_MULTI_USE, ALLOW_MULTI_USE_DEFAULT);
    }

    /**
     * The record of the key with this point encoding and identity, made if there is none.
     */
    static Record recordFor(byte[] point, byte[] identity)
    {
        Record made = new Record(fingerprint(point, identity));
        synchronized (SM9KeyUsageGuard.class)
        {
            WeakReference ref = (WeakReference)records.get(made);
            Record record = (ref == null) ? null : (Record)ref.get();
            if (record == null)
            {
                // a record that has gone took its entry with it, being the entry's key as well as its
                // value, so this files the new record rather than replacing the value of a dying entry
                record = made;
                records.put(record, new WeakReference(record));
            }
            return record;
        }
    }

    /**
     * Hold the key the record is for to usage - {@link SM9EncPrivateKeyParameters#USAGE_KEM} or
     * {@link SM9EncPrivateKeyParameters#USAGE_DECRYPTION} - unless it is held to another already. The
     * one caller, {@link SM9EncPrivateKeyParameters#recordUsage(int)}, refuses any other usage first:
     * USAGE_UNSPECIFIED marks a record held to neither, so it is never claimed.
     *
     * @return the usage the key is held to after the call: usage, or the one it was held to before.
     */
    static int claim(Record record, int usage)
    {
        synchronized (SM9KeyUsageGuard.class)
        {
            touch(record);
            if (record.usage == SM9EncPrivateKeyParameters.USAGE_UNSPECIFIED)
            {
                record.usage = usage;
            }
            return record.usage;
        }
    }

    // under the class lock: make the record the newest of those held, letting go of the oldest once
    // more than RECENT are
    private static void touch(Record record)
    {
        if (record.next != null)
        {
            unlink(record);
        }
        record.next = recent.next;
        record.prev = recent;
        recent.next.prev = record;
        recent.next = record;
        if (++recentCount > RECENT)
        {
            unlink(recent.prev);
        }
    }

    // under the class lock: take the record out of the ring
    private static void unlink(Record record)
    {
        record.prev.next = record.next;
        record.next.prev = record.prev;
        record.next = null;
        record.prev = null;
        recentCount--;
    }

    // SM3 over the point, of fixed length, and the identity. No key of the guard's own goes in: the
    // point is secret already, so only a holder of the key can form the digest
    private static byte[] fingerprint(byte[] point, byte[] identity)
    {
        SM3Digest digest = new SM3Digest();
        digest.update(point, 0, point.length);
        digest.update(identity, 0, identity.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /**
     * What one key value has been used for, found by its fingerprint. The usage and the ring links are
     * read and written under the class lock.
     */
    static final class Record
    {
        private final byte[] fingerprint;
        private final int hash;
        // USAGE_UNSPECIFIED until the key is first held to one of the two
        int usage = SM9EncPrivateKeyParameters.USAGE_UNSPECIFIED;
        // the neighbours in the ring of recent records, both null while the record is not in it
        Record next;
        Record prev;

        // the ring's sentinel, which is no key's record
        Record()
        {
            this.fingerprint = null;
            this.hash = 0;
            this.next = this;
            this.prev = this;
        }

        Record(byte[] fingerprint)
        {
            this.fingerprint = fingerprint;
            this.hash = Arrays.hashCode(fingerprint);
        }

        public boolean equals(Object o)
        {
            return o instanceof Record && Arrays.areEqual(fingerprint, ((Record)o).fingerprint);
        }

        public int hashCode()
        {
            return hash;
        }
    }
}
