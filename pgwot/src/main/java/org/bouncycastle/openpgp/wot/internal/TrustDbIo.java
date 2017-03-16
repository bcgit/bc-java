package org.bouncycastle.openpgp.wot.internal;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.wot.Config;
import org.bouncycastle.openpgp.wot.TrustConst;
import org.bouncycastle.openpgp.wot.TrustDbIoException;
import org.bouncycastle.openpgp.wot.internal.TrustRecord.HashLst;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IO layer for <a href="https://gnupg.org/">GnuPG</a>'s {@code trustdb.gpg}.
 * <p>
 * An instance of this class is used to read from and write to the {@code trustdb.gpg}, which is usually located in
 * {@code ~/.gnupg/}. If this file does not exist (yet), it is created. The containing directory, however, is not
 * created implicitly!
 * <p>
 * <b>Important:</b> Do <b>not</b> use this class directly, if you don't have good reasons to! Instead, you should use
 * the {@link TrustDbImpl}.
 * <p>
 * This class was mostly ported from the GnuPG's {@code tdbio.h} and {@code tdbio.c} files.
 */
class TrustDbIo implements AutoCloseable, TrustConst
{
    private static final Logger logger = LoggerFactory.getLogger(TrustDbIo.class);

    private final SortedMap<Long, TrustRecord> dirtyRecordNum2TrustRecord = new TreeMap<>();
    private final LinkedHashSet<Long> cacheRecordNums = new LinkedHashSet<Long>();
    private final Map<Long, TrustRecord> cacheRecordNum2TrustRecord = new HashMap<>();

    private final File file;
    private final Mutex mutex;
    private final RandomAccessFile raf;
    private final FileLock fileLock;
    private boolean closed;

    /**
     * Create an instance of {@code TrustDbIo} with the given file (usually named {@code trustdb.gpg}).
     * <p>
     * <b>Important:</b> You must {@linkplain #close() close} this instance!
     *
     * @param file
     *            the file to read from and write to. Must not be <code>null</code>. Is created, if not yet existing.
     * @param mutex the mutex used for the pgp/gnupg directory the given {@code trustdb.gpg} belongs to. Must not be <code>null</code>.
     * @throws TrustDbIoException
     *             if reading from/writing to the {@code trustdb.gpg} failed.
     */
    public TrustDbIo(final File file, final Mutex mutex) throws TrustDbIoException
    {
        this.file = assertNotNull("file", file);
        this.mutex = assertNotNull("mutex", mutex);
        RandomAccessFile raf = null;
        FileLock fileLock = null;
        try
        {
            raf = new RandomAccessFile(file, "rw");

            // Try to lock the file for 60 seconds - using tryLock() instead of lock(), because I ran
            // into exceptions already, even though lock() should wait according to javadoc.
            final int timeoutMillis = 60 * 1000;
            final int sleepMillis = 500;
            final int tryCount = timeoutMillis / sleepMillis;
            for (int i = 0; i < tryCount; ++i)
            {
                if (fileLock == null && i != 0) {
                    logger.warn("Locking file '{}' failed. Retrying.", file.getAbsolutePath());
                    try
                    {
                        Thread.sleep(sleepMillis);
                    } catch (InterruptedException e)
                    {
                        doNothing(); // ignore
                    }
                }

                try
                {
                    fileLock = raf.getChannel().tryLock();
                } catch (OverlappingFileLockException y)
                {
                    doNothing(); // ignore (it's quite strange that *try*Lock() might still throw this exception at all)
                }
                if (fileLock != null)
                    break;
            }

            if (fileLock == null)
                fileLock = raf.getChannel().lock();

        } catch (IOException x) {
            throw new TrustDbIoException(x);
        } finally {
            // If opening the file succeeded, but locking it failed, we must close the RandomAccessFile now.
            if (fileLock == null && raf != null) {
                try {
                    // We only come here, if there's currently an exception flying. Hence, we close the file
                    // inside this new try-catch-block in order to prevent the primary exception from being
                    // lost. A new exception otherwise would suppress the primary exception.
                    raf.close();
                } catch (Exception e) {
                    logger.warn("Closing file failed: " + e, e);
                }
            }
        }
        this.raf = raf;
        this.fileLock = fileLock;

        if (getTrustRecord(0, TrustRecord.Version.class) == null)
            createVersionRecord();
    }

    private void createVersionRecord() throws TrustDbIoException
    {
        final Config config = Config.getInstance();

        TrustRecord.Version version = new TrustRecord.Version();
        version.setVersion((short) 3);
        version.setCreated(new Date());
        version.setNextCheck(version.getCreated()); // we should check it as soon as possible
        version.setMarginalsNeeded(config.getMarginalsNeeded());
        version.setCompletesNeeded(config.getCompletesNeeded());
        version.setCertDepth(config.getMaxCertDepth());
        version.setTrustModel(config.getTrustModel()); // TODO maybe support other trust-models, too - currently only
                                                       // PGP is supported!
        version.setMinCertLevel(config.getMinCertLevel());

        version.setRecordNum(0);
        putTrustRecord(version);
        flush();
    }

    public void updateVersionRecord(final Date nextCheck) throws TrustDbIoException
    {
        synchronized (mutex) {
            assertNotNull("nextCheck", nextCheck);

            TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
            assertNotNull("version", version);

            Config config = Config.getInstance();

            version.setCreated(new Date());
            version.setNextCheck(nextCheck);
            version.setMarginalsNeeded(config.getMarginalsNeeded());
            version.setCompletesNeeded(config.getCompletesNeeded());
            version.setCertDepth(config.getMaxCertDepth());
            version.setTrustModel(config.getTrustModel());
            version.setMinCertLevel(config.getMinCertLevel());

            putTrustRecord(version);
        }
    }

    public TrustRecord getTrustRecord(final long recordNum) throws TrustDbIoException
    {
        synchronized (mutex) {
            return getTrustRecord(recordNum, TrustRecord.class);
        }
    }

    public TrustRecord.Trust getTrustByPublicKey(PGPPublicKey pk) throws TrustDbIoException
    {
        synchronized (mutex) {
            final byte[] fingerprint = pk.getFingerprint();
            return getTrustByFingerprint(fingerprint);
        }
    }

    /** Record number of the trust hashtable. */
    private long trustHashRec = 0;

    protected long getTrustHashRec()
    {
        synchronized (mutex) {
            if (trustHashRec == 0)
            {
                TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
                assertNotNull("version", version);

                trustHashRec = version.getTrustHashTbl();
                if (trustHashRec == 0)
                {
                    createHashTable(0);
                    trustHashRec = version.getTrustHashTbl();
                }
            }
            return trustHashRec;
        }
    }

    /**
     * Append a new empty hashtable to the trustdb. TYPE gives the type of the hash table. The only defined type is 0
     * for a trust hash. On return the hashtable has been created, written, the version record updated, and the data
     * flushed to the disk. On a fatal error the function terminates the process.
     */
    private void createHashTable(int type) throws TrustDbIoException
    {
        TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
        assertNotNull("version", version);

        flush(); // make sure, raf.length is correct.

        long offset;
        long recnum;

        try
        {
            offset = raf.length();
            raf.seek(offset);
        } catch (IOException e)
        {
            throw new TrustDbIoException(e);
        }

        recnum = offset / TRUST_RECORD_LEN;
        if (recnum <= 0) // This is will never be the first record.
            throw new IllegalStateException("recnum <= 0");

        if (type == 0)
            version.setTrustHashTbl(recnum);

        // Now write the records making up the hash table.
        final int n = (256 + ITEMS_PER_HTBL_RECORD - 1) / ITEMS_PER_HTBL_RECORD;
        for (int i = 0; i < n; ++i, ++recnum)
        {
            TrustRecord.HashTbl hashTable = new TrustRecord.HashTbl();
            hashTable.setRecordNum(recnum);
            putTrustRecord(hashTable);
        }
        // Update the version record and flush.
        putTrustRecord(version);
        flush();
    }

    // ulong tdbio_new_recnum ()
    protected long newRecordNum() throws TrustDbIoException
    {
        synchronized (mutex) {
            long recordNum;

            // Look for Free records.
            final TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
            assertNotNull("version", version);

            if (version.getFirstFree() != 0)
            {
                recordNum = version.getFirstFree();
                TrustRecord.Free free = getTrustRecord(recordNum, TrustRecord.Free.class);
                assertNotNull("free", free);

                // Update dir record.
                version.setFirstFree(free.getNext());
                putTrustRecord(version);

                // Zero out the new record. Means we convert from Free to Unused.
                // => Done at the end!
            }
            else
            { // Not found - append a new record.
                final long fileLength;
                try
                {
                    fileLength = raf.length();
                } catch (IOException e)
                {
                    throw new TrustDbIoException(e);
                }
                recordNum = fileLength / TRUST_RECORD_LEN;

                if (recordNum < 1) // this is will never be the first record
                    throw new IllegalStateException("recnum < 1");

                // Maybe our file-length is not up-to-date => consult the dirty records.
                if (!dirtyRecordNum2TrustRecord.isEmpty())
                {
                    long lastDirtyRecordNum = dirtyRecordNum2TrustRecord.lastKey();
                    if (lastDirtyRecordNum >= recordNum)
                        recordNum = lastDirtyRecordNum + 1;
                }

                // We must add a record, so that the next call to this function returns another recnum.
                // => Done at the end!
            }

            final TrustRecord.Unused unused = new TrustRecord.Unused();
            unused.setRecordNum(recordNum);
            putTrustRecord(unused);

            return recordNum;
        }
    }

    public TrustRecord.Trust getTrustByFingerprint(final byte[] fingerprint) throws TrustDbIoException
    {
        synchronized (mutex) {
            /* Locate the trust record using the hash table */
            TrustRecord rec = getTrustRecordViaHashTable(getTrustHashRec(), fingerprint, new TrustRecordMatcher()
            {
                @Override
                public boolean matches(final TrustRecord trustRecord)
                {
                    if (!(trustRecord instanceof TrustRecord.Trust))
                        return false;

                    final TrustRecord.Trust trust = (TrustRecord.Trust) trustRecord;
                    return Arrays.equals(trust.getFingerprint(), fingerprint);
                }
            });
            return (TrustRecord.Trust) rec;
        }
    }

    private static interface TrustRecordMatcher
    {
        boolean matches(TrustRecord trustRecord);
    }

    // static gpg_error_t lookup_hashtable (ulong table, const byte *key, size_t keylen, int (*cmpfnc)(const void*,
    // const TRUSTREC *), const void *cmpdata, TRUSTREC *rec )
    public TrustRecord getTrustRecordViaHashTable(long table, byte[] key, TrustRecordMatcher matcher)
    {
        synchronized (mutex) {
            long hashrec, item;
            int msb;
            int level = 0;

            hashrec = table;
            next_level: while (true)
            {
                msb = key[level] & 0xff;
                hashrec += msb / ITEMS_PER_HTBL_RECORD;
                TrustRecord.HashTbl hashTable = getTrustRecord(hashrec, TrustRecord.HashTbl.class);
                // assertNotNull("hashTable", hashTable);
                if (hashTable == null)
                    return null; // not found!

                item = hashTable.getItem(msb % ITEMS_PER_HTBL_RECORD);
                if (item == 0)
                    return null; // not found!

                TrustRecord record = getTrustRecord(item);
                assertNotNull("record", record);

                if (record.getType() == TrustRecordType.HTBL)
                {
                    hashrec = item;
                    if (++level >= key.length)
                        throw new TrustDbIoException("hashtable has invalid indirections");

                    continue next_level;
                }

                if (record.getType() == TrustRecordType.HLST)
                {
                    TrustRecord.HashLst hashList = (TrustRecord.HashLst) record;

                    for (;;)
                    {
                        for (int i = 0; i < ITEMS_PER_HLST_RECORD; i++)
                        {
                            if (hashList.getRNum(i) != 0)
                            {
                                TrustRecord tmp = getTrustRecord(hashList.getRNum(i));
                                if (tmp != null && matcher.matches(tmp))
                                    return tmp;
                            }
                        }

                        if (hashList.getNext() != 0)
                        {
                            hashList = getTrustRecord(hashList.getNext(), TrustRecord.HashLst.class);
                            assertNotNull("hashList", hashList);
                        }
                        else
                            return null;
                    }
                }

                if (matcher.matches(record))
                    return record;
                else
                    return null;
            }
        }
    }

    public <T extends TrustRecord> T getTrustRecord(final long recordNum, Class<T> expectedTrustRecordClass)
            throws TrustDbIoException
    {
        synchronized (mutex) {
            assertNotNull("expectedTrustRecordClass", expectedTrustRecordClass);
            final TrustRecordType expectedType = expectedTrustRecordClass ==
                    TrustRecord.class ? null : TrustRecordType.fromClass(expectedTrustRecordClass);

            TrustRecord record = getFromCache(recordNum);
            if (record == null)
            {
                try
                {
                    raf.seek(recordNum * TRUST_RECORD_LEN);
                } catch (IOException x)
                {
                    throw new TrustDbIoException(x);
                }

                final byte[] buf = new byte[TRUST_RECORD_LEN];
                try
                {
                    raf.readFully(buf);
                } catch (EOFException x)
                {
                    return null;
                } catch (IOException x)
                {
                    throw new TrustDbIoException(x);
                }

                int bufIdx = 0;

                final TrustRecordType type = TrustRecordType.fromId((short) (buf[bufIdx++] & 0xFF));
                if (expectedType != null && !expectedType.equals(type))
                    throw new IllegalStateException(String.format("expectedType != foundType :: %s != %s", expectedType,
                            type));

                ++bufIdx; // Skip reserved byte.

                switch (type)
                {
                    case UNUSED: // unused (free) record
                        record = new TrustRecord.Unused();
                        break;
                    case VERSION: // version record
                        final TrustRecord.Version version = new TrustRecord.Version();
                        record = version;

                        --bufIdx; // undo skip reserved byte, because this does not apply to VERSION record.
                        if (buf[bufIdx++] != 'g'
                                || buf[bufIdx++] != 'p'
                                || buf[bufIdx++] != 'g')
                            throw new TrustDbIoException(String.format("Not a trustdb file: %s", file.getAbsolutePath()));

                        version.version = (short) (buf[bufIdx++] & 0xFF);
                        version.marginalsNeeded = (short) (buf[bufIdx++] & 0xFF);
                        version.completesNeeded = (short) (buf[bufIdx++] & 0xFF);
                        version.certDepth = (short) (buf[bufIdx++] & 0xFF);
                        version.trustModel = (short) (buf[bufIdx++] & 0xFF);
                        version.minCertLevel = (short) (buf[bufIdx++] & 0xFF);

                        bufIdx += 2; // no idea why, but we have to skip 2 bytes
                        version.created = new Date(1000L * (bytesToInt(buf, bufIdx) & 0xFFFFFFFFL));
                        bufIdx += 4;
                        version.nextCheck = new Date(1000L * (bytesToInt(buf, bufIdx) & 0xFFFFFFFFL));
                        bufIdx += 4;
                        bufIdx += 4; // no idea why, but we have to skip 4 bytes
                        bufIdx += 4; // no idea why, but we have to skip 4 bytes
                        version.firstFree = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;
                        bufIdx += 4; // no idea why, but we have to skip 4 bytes
                        version.trustHashTbl = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;

                        if (version.version != 3)
                            throw new TrustDbIoException(String.format(
                                    "Wrong version number (3 expected, but %d found): %s", version.version,
                                    file.getAbsolutePath()));
                        break;
                    case FREE:
                        final TrustRecord.Free free = new TrustRecord.Free();
                        record = free;
                        free.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;
                        break;
                    case HTBL:
                        final TrustRecord.HashTbl hashTbl = new TrustRecord.HashTbl();
                        record = hashTbl;
                        for (int i = 0; i < ITEMS_PER_HTBL_RECORD; ++i)
                        {
                            hashTbl.item[i] = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                            bufIdx += 4;
                        }
                        break;
                    case HLST:
                        final TrustRecord.HashLst hashLst = new TrustRecord.HashLst();
                        record = hashLst;
                        hashLst.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;
                        for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i)
                        {
                            hashLst.rnum[i] = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                            bufIdx += 4;
                        }
                        break;
                    case TRUST:
                        final TrustRecord.Trust trust = new TrustRecord.Trust();
                        record = trust;
                        System.arraycopy(buf, bufIdx, trust.fingerprint, 0, 20);
                        bufIdx += 20;
                        trust.ownerTrust = (short) (buf[bufIdx++] & 0xFF);
                        trust.depth = (short) (buf[bufIdx++] & 0xFF);
                        trust.minOwnerTrust = (short) (buf[bufIdx++] & 0xFF);
                        ++bufIdx; // no idea why, but we have to skip 1 byte
                        trust.validList = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;
                        break;
                    case VALID:
                        final TrustRecord.Valid valid = new TrustRecord.Valid();
                        record = valid;
                        System.arraycopy(buf, bufIdx, valid.nameHash, 0, 20);
                        bufIdx += 20;
                        valid.validity = (short) (buf[bufIdx++] & 0xFF);
                        valid.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL;
                        bufIdx += 4;
                        valid.fullCount = (short) (buf[bufIdx++] & 0xFF);
                        valid.marginalCount = (short) (buf[bufIdx++] & 0xFF);
                        break;
                    default:
                        throw new IllegalArgumentException("Unexpected TrustRecordType: " + type);
                }
                record.recordNum = recordNum;
                putToCache(record);
            }
            else
            {
                if (expectedType != null && !expectedType.equals(record.getType()))
                    throw new IllegalStateException(String.format("expectedType != foundType :: %s != %s", expectedType,
                            record.getType()));
            }

            return expectedTrustRecordClass.cast(record);
        }
    }

    public void putTrustRecord(final TrustRecord trustRecord) throws TrustDbIoException
    {
        synchronized (mutex) {
            assertNotNull("trustRecord", trustRecord);

            if (trustRecord.getRecordNum() < 0)
                trustRecord.setRecordNum(newRecordNum());

            putToCache(trustRecord);

            final long recordNum = trustRecord.getRecordNum();
            dirtyRecordNum2TrustRecord.put(recordNum, trustRecord);

            if (trustRecord instanceof TrustRecord.Trust)
                updateHashTable(getTrustHashRec(), ((TrustRecord.Trust) trustRecord).getFingerprint(), recordNum);
        }
    }

    protected void writeTrustRecord(final TrustRecord record) throws TrustDbIoException
    {
        synchronized (mutex) {
            int bufIdx = 0;
            final byte[] buf = new byte[TRUST_RECORD_LEN];

            buf[bufIdx++] = (byte) record.getType().getId();
            ++bufIdx; // Skip reserved byte.

            switch (record.getType())
            {
                case UNUSED: // unused (free) record
                    break;
                case VERSION: // version record
                    final TrustRecord.Version version = (TrustRecord.Version) record;

                    --bufIdx; // undo skip reserved byte, because this does not apply to VERSION record.
                    buf[bufIdx++] = 'g';
                    buf[bufIdx++] = 'p';
                    buf[bufIdx++] = 'g';

                    buf[bufIdx++] = (byte) version.version;
                    buf[bufIdx++] = (byte) version.marginalsNeeded;
                    buf[bufIdx++] = (byte) version.completesNeeded;
                    buf[bufIdx++] = (byte) version.certDepth;
                    buf[bufIdx++] = (byte) version.trustModel;
                    buf[bufIdx++] = (byte) version.minCertLevel;

                    bufIdx += 2; // no idea why, but we have to skip 2 bytes

                    intToBytes((int) (version.created.getTime() / 1000L), buf, bufIdx);
                    bufIdx += 4;
                    intToBytes((int) (version.nextCheck.getTime() / 1000L), buf, bufIdx);
                    bufIdx += 4;
                    bufIdx += 4; // no idea why, but we have to skip 4 bytes
                    bufIdx += 4; // no idea why, but we have to skip 4 bytes
                    intToBytes((int) version.firstFree, buf, bufIdx);
                    bufIdx += 4;
                    bufIdx += 4; // no idea why, but we have to skip 4 bytes
                    intToBytes((int) version.trustHashTbl, buf, bufIdx);
                    bufIdx += 4;

                    if (version.version != 3)
                        throw new TrustDbIoException(String.format("Wrong version number (3 expected, but %d found): %s",
                                version.version, file.getAbsolutePath()));
                    break;
                case FREE:
                    final TrustRecord.Free free = (TrustRecord.Free) record;
                    intToBytes((int) free.next, buf, bufIdx);
                    bufIdx += 4;
                    break;
                case HTBL:
                    final TrustRecord.HashTbl hashTbl = (TrustRecord.HashTbl) record;
                    for (int i = 0; i < ITEMS_PER_HTBL_RECORD; ++i)
                    {
                        intToBytes((int) hashTbl.item[i], buf, bufIdx);
                        bufIdx += 4;
                    }
                    break;
                case HLST:
                    final TrustRecord.HashLst hashLst = (TrustRecord.HashLst) record;
                    intToBytes((int) hashLst.next, buf, bufIdx);
                    bufIdx += 4;
                    for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i)
                    {
                        intToBytes((int) hashLst.rnum[i], buf, bufIdx);
                        bufIdx += 4;
                    }
                    break;
                case TRUST:
                    final TrustRecord.Trust trust = (TrustRecord.Trust) record;
                    System.arraycopy(trust.fingerprint, 0, buf, bufIdx, 20);
                    bufIdx += 20;
                    buf[bufIdx++] = (byte) trust.ownerTrust;
                    buf[bufIdx++] = (byte) trust.depth;
                    buf[bufIdx++] = (byte) trust.minOwnerTrust;
                    ++bufIdx; // no idea why, but we have to skip 1 byte
                    intToBytes((int) trust.validList, buf, bufIdx);
                    bufIdx += 4;
                    break;
                case VALID:
                    final TrustRecord.Valid valid = (TrustRecord.Valid) record;
                    System.arraycopy(valid.nameHash, 0, buf, bufIdx, 20);
                    bufIdx += 20;
                    buf[bufIdx++] = (byte) valid.validity;
                    intToBytes((int) valid.next, buf, bufIdx);
                    bufIdx += 4;
                    buf[bufIdx++] = (byte) valid.fullCount;
                    buf[bufIdx++] = (byte) valid.marginalCount;
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected TrustRecordType: " + record.getType());
            }

            try
            {
                raf.seek(record.getRecordNum() * TRUST_RECORD_LEN);
                raf.write(buf);
            } catch (IOException e)
            {
                throw new TrustDbIoException(e);
            }
        }
    }

    /**
     * Update a hashtable in the trustdb. TABLE gives the start of the table, KEY and KEYLEN are the key, NEWRECNUM is
     * the record number to insert into the table.
     *
     * Return: 0 on success or an error code.
     */
    // static int upd_hashtable (ulong table, byte *key, int keylen, ulong newrecnum)
    protected void updateHashTable(long table, byte[] key, long recordNum) throws TrustDbIoException
    {
        synchronized (mutex) {
            // TrustRecord lastrec, rec;
            TrustRecord.HashTbl lastHashTable = null;
            long hashrec, item;
            int msb;
            int level = 0;

            hashrec = table;
            next_level: while (true)
            {
                msb = key[level] & 0xff;
                hashrec += msb / ITEMS_PER_HTBL_RECORD;

                TrustRecord.HashTbl hashTable = getTrustRecord(hashrec, TrustRecord.HashTbl.class);
                item = hashTable.getItem(msb % ITEMS_PER_HTBL_RECORD);
                if (item == 0)
                { // Insert a new item into the hash table.
                    hashTable.setItem(msb % ITEMS_PER_HTBL_RECORD, recordNum);
                    putTrustRecord(hashTable);
                    return;
                }
                else if (item == recordNum)
                { // perfect match ;-)
                    return;
                }
                else
                { // Must do an update.
                    lastHashTable = hashTable;
                    hashTable = null;
                    TrustRecord rec = getTrustRecord(item);
                    if (rec.getType() == TrustRecordType.HTBL)
                    {
                        hashrec = item;
                        ++level;
                        if (level >= key.length)
                            throw new TrustDbIoException("hashtable has invalid indirections.");

                        continue next_level;
                    }
                    else if (rec.getType() == TrustRecordType.HLST)
                    { // Extend the list.
                        TrustRecord.HashLst hashList = (HashLst) rec;
                        // Check whether the key is already in this list.
                        for (;;)
                        {
                            for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i)
                            {
                                if (hashList.getRNum(i) == recordNum)
                                    return; // Okay, already in the list.
                            }

                            if (hashList.getNext() == 0)
                                break; // key is not in the list

                            hashList = getTrustRecord(hashList.getNext(), TrustRecord.HashLst.class);
                            assertNotNull("hashList", hashList);
                        }

                        // The following line was added by me, Marco. I think the original GnuPG code missed this: We should
                        // start looking
                        // for a free entry in the *first* suitable HashList record again, because there might have been
                        // sth. dropped.
                        hashList = (HashLst) rec;

                        // Find the next free entry and put it in.
                        for (;;)
                        {
                            for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i)
                            {
                                if (hashList.getRNum(i) == 0)
                                {
                                    // Empty slot found.
                                    hashList.setRnum(i, recordNum);
                                    putTrustRecord(hashList);
                                    return; // Done.
                                }
                            }

                            if (hashList.getNext() != 0)
                            {
                                // read the next reord of the list.
                                hashList = getTrustRecord(hashList.getNext(), TrustRecord.HashLst.class);
                            }
                            else
                            {
                                // Append a new record to the list.
                                TrustRecord.HashLst old = hashList;
                                hashList = new TrustRecord.HashLst();
                                hashList.setRnum(0, recordNum);

                                putTrustRecord(hashList); // assigns the new recordNum, too
                                old.setNext(hashList.getRecordNum());
                                putTrustRecord(old);
                                return; // Done.
                            }
                        } /* end loop over list slots */
                    }
                    else
                    { // Insert a list record.
                        if (rec.getType() != TrustRecordType.TRUST)
                            throw new IllegalStateException(String.format(
                                    "hashtbl %d: %d/%d points to an invalid record %d",
                                    table, hashrec, (msb % ITEMS_PER_HTBL_RECORD), item));

                        if (rec.getRecordNum() == recordNum)
                            return; // found - fine - no need to change anything ;-)

                        TrustRecord.HashLst hashList = new TrustRecord.HashLst();
                        hashList.setRnum(0, rec.getRecordNum()); // Old key record
                        hashList.setRnum(1, recordNum); // and new key record
                        putTrustRecord(hashList);

                        // Update the hashtable record.
                        assertNotNull("lastHashTable", lastHashTable).setItem(msb % ITEMS_PER_HTBL_RECORD,
                                hashList.getRecordNum());
                        putTrustRecord(lastHashTable);
                        return;
                    }
                }
            }
        }
    }

    private TrustRecord getFromCache(final long recordNum)
    {
        final TrustRecord trustRecord = cacheRecordNum2TrustRecord.get(recordNum);
        logger.trace("getFromCache: recordNum={} found={}", recordNum, trustRecord != null);
        return trustRecord;
    }

    private void putToCache(TrustRecord trustRecord)
    {
        assertNotNull("trustRecord", trustRecord);
        final long recordNum = trustRecord.getRecordNum();

        if (cacheRecordNum2TrustRecord.containsKey(recordNum))
            cacheRecordNums.remove(recordNum);

        while (cacheRecordNums.size() + 1 > MAX_CACHE_SIZE)
        {
            final Long oldestRecordNum = cacheRecordNums.iterator().next();
            cacheRecordNums.remove(oldestRecordNum);
            cacheRecordNum2TrustRecord.remove(oldestRecordNum);
        }

        cacheRecordNum2TrustRecord.put(recordNum, trustRecord);
        cacheRecordNums.add(recordNum);
    }

    public void flush() throws TrustDbIoException
    {
        synchronized (mutex) {
            for (TrustRecord trustRecord : dirtyRecordNum2TrustRecord.values())
                writeTrustRecord(trustRecord);

            dirtyRecordNum2TrustRecord.clear();

            try
            {
                raf.getFD().sync();
            } catch (IOException e)
            {
                throw new TrustDbIoException(e);
            }
        }
    }

    @Override
    public void close() throws TrustDbIoException
    {
        synchronized (mutex) {
            if (closed)
                return;

            flush();
            closed = true;
            try
            {
                fileLock.release();
                raf.close();
            } catch (IOException e)
            {
                throw new TrustDbIoException(e);
            }
        }
    }
}
