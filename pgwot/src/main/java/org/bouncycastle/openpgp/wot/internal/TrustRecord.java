package org.bouncycastle.openpgp.wot.internal;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.openpgp.wot.TrustConst;

/**
 * A {@code TrustRecord} represents a row in the trust database - which is actually one big table.
 * <p>
 * Each row in the trust database can have a different purpose, thus there are different types -
 * modeled both via {@link TrustRecordType} and via sub-classes of {@code TrustRecord}.
 * <p>
 * <b>Important:</b> Reading or modifying a TrustRecord must always be done in a synchronized block
 * (using {@link Mutex}) guaranteeing the consistency of the entire trust database. There are
 * inter-dependencies between different records inside the trust database and failing to synchronize
 * might corrupt the entire database!
 * <p>
 * Ported from tdbio.c: struct trust_record
 */
abstract class TrustRecord implements TrustConst
{
    protected long recordNum = -1;

    static class Unused extends TrustRecord
    {
        @Override
        public TrustRecordType getType()
        {
            return TrustRecordType.UNUSED;
        }
    }

    static class Version extends TrustRecord
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

    static class Free extends TrustRecord
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

    static class HashTbl extends TrustRecord
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

    static class HashLst extends TrustRecord
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

    static class Trust extends TrustRecord
    {
        protected byte[] fingerprint = new byte[20];
        protected short ownerTrust;
        protected short depth;
        protected long validList;
        protected short minOwnerTrust;

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

    static class Valid extends TrustRecord
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
}
