package org.bouncycastle.openpgp.wot.internal;

import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.openpgp.wot.TrustConst;

public abstract class TrustRecord implements TrustConst
{

    protected long recordNum = -1;

    public static class Unused extends TrustRecord
    {
        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.UNUSED;
        }
    }

    public static class Version extends TrustRecord
    {
        protected short version; // should be 3
        protected short marginalsNeeded;
        protected short completesNeeded;
        protected short certDepth;
        protected short trustModel;
        protected short minCertLevel;
        protected Date created; // timestamp of trustdb creation
        protected Date nextCheck; // timestamp of next scheduled check
        protected long reserved;
        protected long reserved2;
        protected long firstFree;
        protected long reserved3;
        protected long trustHashTbl;

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.VERSION;
        }

        public short getVersion()
        {
            return version;
        }

        public void setVersion(short version)
        {
            this.version = version;
        }

        public short getMarginalsNeeded()
        {
            return marginalsNeeded;
        }

        public void setMarginalsNeeded(short marginals)
        {
            this.marginalsNeeded = marginals;
        }

        public short getCompletesNeeded()
        {
            return completesNeeded;
        }

        public void setCompletesNeeded(short completes)
        {
            this.completesNeeded = completes;
        }

        public short getCertDepth()
        {
            return certDepth;
        }

        public void setCertDepth(short certDepth)
        {
            this.certDepth = certDepth;
        }

        public short getTrustModel()
        {
            return trustModel;
        }

        public void setTrustModel(short trustModel)
        {
            this.trustModel = trustModel;
        }

        public short getMinCertLevel()
        {
            return minCertLevel;
        }

        public void setMinCertLevel(short minCertLevel)
        {
            this.minCertLevel = minCertLevel;
        }

        public Date getCreated()
        {
            return created;
        }

        public void setCreated(Date created)
        {
            this.created = created;
        }

        public Date getNextCheck()
        {
            return nextCheck;
        }

        public void setNextCheck(Date nextCheck)
        {
            this.nextCheck = nextCheck;
        }

        public long getReserved()
        {
            return reserved;
        }

        public long getReserved2()
        {
            return reserved2;
        }

        public long getFirstFree()
        {
            return firstFree;
        }

        public void setFirstFree(long firstFree)
        {
            this.firstFree = firstFree;
        }

        public long getReserved3()
        {
            return reserved3;
        }

        public long getTrustHashTbl()
        {
            return trustHashTbl;
        }

        public void setTrustHashTbl(long trustHashTbl)
        {
            this.trustHashTbl = trustHashTbl;
        }

        @Override
        public String toString()
        {
            return String.format("%s[recordNum=%d version=%d marginalsNeeded=%d completesNeeded=%d certDepth=%d trustModel=%d minCertLevel=%d created=%s nextCheck=%s reserved=%d reserved2=%d firstFree=%d reserved3=%d trustHashTbl=%d]",
                    getClass().getSimpleName(), recordNum, version, marginalsNeeded,
                    completesNeeded, certDepth, trustModel, minCertLevel,
                    created, nextCheck, reserved, reserved2, firstFree, reserved3, trustHashTbl);
        }
    }

    public static class Free extends TrustRecord
    {
        protected long next;

        public long getNext()
        {
            return next;
        }

        public void setNext(long next)
        {
            if (next < 0)
                throw new IllegalArgumentException("next < 0");

            this.next = next;
        }

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.FREE;
        }

        @Override
        public String toString()
        {
            return String.format("%s[recordNum=%d next=%d]",
                    getClass().getSimpleName(), recordNum, next);
        }
    }

    public static class HashTbl extends TrustRecord
    {
        protected long[] item = new long[ITEMS_PER_HTBL_RECORD];

        public long getItem(int index)
        {
            return item[index];
        }

        public void setItem(int index, long value)
        {
            if (value < 0)
                throw new IllegalArgumentException("value < 0");

            item[index] = value;
        }

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.HTBL;
        }

        @Override
        public String toString()
        {
            return String.format("%s[recordNum=%d item=%s]",
                    getClass().getSimpleName(), recordNum, Arrays.toString(item));
        }
    }

    public static class HashLst extends TrustRecord
    {
        protected long next;
        protected long[] rnum = new long[ITEMS_PER_HLST_RECORD]; // of another record

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.HLST;
        }

        public long getRNum(int index)
        {
            return rnum[index];
        }

        public void setRnum(int index, long value)
        {
            if (value < 0)
                throw new IllegalArgumentException("value < 0");

            rnum[index] = value;
        }

        public long getNext()
        {
            return next;
        }

        public void setNext(long next)
        {
            if (next < 0)
                throw new IllegalArgumentException("next < 0");

            this.next = next;
        }

        @Override
        public String toString()
        {
            return String.format("%s[recordNum=%d next=%d rnum=%s]",
                    getClass().getSimpleName(), recordNum, next, Arrays.toString(rnum));
        }
    }

    public static class Trust extends TrustRecord
    {
        protected byte[] fingerprint = new byte[20];
        protected short ownerTrust;
        protected short depth;
        protected long validList;
        protected short minOwnerTrust;

        public Trust()
        {
        }

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.TRUST;
        }

        public byte[] getFingerprint()
        {
            return fingerprint;
        }

        public void setFingerprint(byte[] fingerprint)
        {
            this.fingerprint = fingerprint;
        }

        public short getOwnerTrust()
        {
            return ownerTrust;
        }

        public void setOwnerTrust(short ownerTrust)
        {
            this.ownerTrust = ownerTrust;
        }

        public short getDepth()
        {
            return depth;
        }

        public void setDepth(short depth)
        {
            if (depth < 0)
                throw new IllegalArgumentException("depth < 0");

            this.depth = depth;
        }

        public long getValidList()
        {
            return validList;
        }

        public void setValidList(long validList)
        {
            if (validList < 0)
                throw new IllegalArgumentException("validList < 0");

            this.validList = validList;
        }

        public short getMinOwnerTrust()
        {
            return minOwnerTrust;
        }

        public void setMinOwnerTrust(short minOwnerTrust)
        {
            this.minOwnerTrust = minOwnerTrust;
        }

        @Override
        public String toString()
        {
            return String.format(
                    "%s[recordNum=%d fingerprint=%s ownerTrust=%d depth=%d validList=%d minOwnerTrust=%d]",
                    getClass().getSimpleName(), recordNum, encodeHexStr(fingerprint),
                    ownerTrust, depth, validList, minOwnerTrust);
        }
    }

    public static class Valid extends TrustRecord
    {
        protected byte[] nameHash = new byte[20];
        protected long next;
        protected short validity;
        protected short fullCount;
        protected short marginalCount;

        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.VALID;
        }

        public byte[] getNameHash()
        {
            return nameHash;
        }

        public void setNameHash(byte[] nameHash)
        {
            this.nameHash = nameHash;
        }

        public long getNext()
        {
            return next;
        }

        public void setNext(long next)
        {
            if (next < 0)
                throw new IllegalArgumentException("next < 0");

            this.next = next;
        }

        public short getValidity()
        {
            return validity;
        }

        public void setValidity(short validity)
        {
            this.validity = validity;
        }

        public short getFullCount()
        {
            return fullCount;
        }

        public void setFullCount(short fullCount)
        {
            this.fullCount = fullCount;
        }

        public short getMarginalCount()
        {
            return marginalCount;
        }

        public void setMarginalCount(short marginalCount)
        {
            this.marginalCount = marginalCount;
        }

        @Override
        public String toString()
        {
            return String.format("%s[recordNum=%d nameHash=%s next=%d validity=%d fullCount=%d marginalCount=%d]",
                    getClass().getSimpleName(), recordNum, encodeHexStr(nameHash),
                    next, validity, fullCount, marginalCount);
        }
    };

    public long getRecordNum()
    {
        return recordNum;
    }

    protected void setRecordNum(long recordNum)
    {
        this.recordNum = recordNum;
    }

    public abstract TrustRecordType getType();

    // Copied from tdbio.c:
    // struct trust_record {
    // int rectype;
    // int mark;
    // int dirty; /* for now only used internal by functions */
    // struct trust_record *next; /* help pointer to build lists in memory */
    // ulong recnum;
    // union {
    // struct { /* version record: */
    // byte version; /* should be 3 */
    // byte marginalsNeeded;
    // byte completesNeeded;
    // byte cert_depth;
    // byte trust_model;
    // byte min_cert_level;
    // ulong created; /* timestamp of trustdb creation */
    // ulong nextcheck; /* timestamp of next scheduled check */
    // ulong reserved;
    // ulong reserved2;
    // ulong firstfree;
    // ulong reserved3;
    // ulong trusthashtbl;
    // } ver;
    // struct { /* free record */
    // ulong next;
    // } free;
    // struct {
    // ulong item[ITEMS_PER_HTBL_RECORD];
    // } htbl;
    // struct {
    // ulong next;
    // ulong rnum[ITEMS_PER_HLST_RECORD]; /* of another record */
    // } hlst;
    // struct {
    // byte fingerprint[20];
    // byte ownertrust;
    // byte depth;
    // ulong validlist;
    // byte min_ownertrust;
    // } trust;
    // struct {
    // byte namehash[20];
    // ulong next;
    // byte validity;
    // byte full_count;
    // byte marginal_count;
    // } valid;
    // } r;
    // };

    public static String encodeHexStr(final byte[] buf)
    {
        return encodeHexStr(buf, 0, buf.length);
    }

    /**
     * Encode a byte array into a human readable hex string. For each byte, two hex digits are produced. They are
     * concatenated without any separators.
     *
     * @param buf
     *            The byte array to translate into human readable text.
     * @param pos
     *            The start position (0-based).
     * @param len
     *            The number of bytes that shall be processed beginning at the position specified by <code>pos</code>.
     * @return a human readable string like "fa3d70" for a byte array with 3 bytes and these values.
     * @see #encodeHexStr(byte[])
     * @see #decodeHexStr(String)
     */
    public static String encodeHexStr(final byte[] buf, int pos, int len)
    {
        final StringBuilder hex = new StringBuilder();
        while (len-- > 0)
        {
            final byte ch = buf[pos++];
            int d = (ch >> 4) & 0xf;
            hex.append((char) (d >= 10 ? 'a' - 10 + d : '0' + d));
            d = ch & 0xf;
            hex.append((char) (d >= 10 ? 'a' - 10 + d : '0' + d));
        }
        return hex.toString();
    }
}
