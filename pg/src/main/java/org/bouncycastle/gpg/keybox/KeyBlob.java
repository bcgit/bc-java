package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A PGP blob holds key material.
 */
public class KeyBlob
    extends Blob
{
    private final int blobFlags;
    private final int keyNumber;
    private final List<KeyInformation> keyInformation;
    private final byte[] serialNumber;
    private final int numberOfUserIDs;
    private final List<UserID> userIds;
    private final int numberOfSignatures;
    private final List<Long> expirationTime;
    private final int assignedOwnerTrust;
    private final int allValidity;
    private final long recheckAfter;
    private final long newestTimestamp;
    private final long blobCreatedAt;
    private final byte[] keyBytes;
    private final byte[] reserveBytes;
    private final byte[] checksum;

    protected KeyBlob(int base, long length,
                      BlobType type,
                      int version,
                      int blobFlags,
                      int keyNumber,
                      List<KeyInformation> keyInformation,
                      byte[] serialNumber,
                      int numberOfUserIDs,
                      List<UserID> userIds,
                      int numberOfSignatures,
                      List<Long> expirationTime,
                      int assignedOwnerTrust,
                      int allValidity,
                      long recheckAfter,
                      long newestTimestamp,
                      long blobCreatedAt,
                      byte[] keyBytes,
                      byte[] reserveBytes,
                      byte[] checksum)
    {
        super(base, length, type, version);
        this.blobFlags = blobFlags;
        this.keyNumber = keyNumber;
        this.keyInformation = keyInformation;
        this.serialNumber = serialNumber;
        this.numberOfUserIDs = numberOfUserIDs;
        this.userIds = userIds;
        this.numberOfSignatures = numberOfSignatures;
        this.expirationTime = expirationTime;
        this.assignedOwnerTrust = assignedOwnerTrust;
        this.allValidity = allValidity;
        this.recheckAfter = recheckAfter;
        this.newestTimestamp = newestTimestamp;
        this.blobCreatedAt = blobCreatedAt;
        this.keyBytes = keyBytes;
        this.reserveBytes = reserveBytes;
        this.checksum = checksum;
    }

    KeyBlob(int base, long length, BlobType type, int version, KeyBlobContent content)
    {
        this(base, length, type, version, content.blobFlags, content.keyNumber,
            content.keyInformation, content.serialNumber, content.numberOfUserIDs, content.userIds,
            content.numberOfSignatures, content.expirationTime, content.assignedOwnerTrust,
            content.allValidity, content.recheckAfter, content.newestTimestamp, content.blobCreatedAt,
            content.keyBytes, content.reserveBytes, content.checksum);
    }

    static void verifyDigest(int base, long length, KeyBoxByteBuffer buffer, BlobVerifier blobVerifier)
        throws IOException
    {
        byte[] blobData = buffer.rangeOf(base, (int)(base + length - 20));
        byte[] blobDigest = buffer.rangeOf((int)(base + length - 20), (int)(base + length));

        if (!blobVerifier.isMatched(blobData, blobDigest))
        {
            throw new IOException("Blob with base offset of " + base + " has incorrect digest.");
        }
    }

    static final class KeyBlobContent
    {
        private final int blobFlags;
        private final int keyNumber;
        private final List<KeyInformation> keyInformation;
        private final byte[] serialNumber;
        private final int numberOfUserIDs;
        private final List<UserID> userIds;
        private final int numberOfSignatures;
        private final List<Long> expirationTime;
        private final int assignedOwnerTrust;
        private final int allValidity;
        private final long recheckAfter;
        private final long newestTimestamp;
        private final long blobCreatedAt;
        private final byte[] keyBytes;
        private final byte[] reserveBytes;
        private final byte[] checksum;

        private KeyBlobContent(int blobFlags, int keyNumber, List<KeyInformation> keyInformation,
                               byte[] serialNumber, int numberOfUserIDs, List<UserID> userIds,
                               int numberOfSignatures, List<Long> expirationTime, int assignedOwnerTrust,
                               int allValidity, long recheckAfter, long newestTimestamp, long blobCreatedAt,
                               byte[] keyBytes, byte[] reserveBytes, byte[] checksum)
        {
            this.blobFlags = blobFlags;
            this.keyNumber = keyNumber;
            this.keyInformation = keyInformation;
            this.serialNumber = serialNumber;
            this.numberOfUserIDs = numberOfUserIDs;
            this.userIds = userIds;
            this.numberOfSignatures = numberOfSignatures;
            this.expirationTime = expirationTime;
            this.assignedOwnerTrust = assignedOwnerTrust;
            this.allValidity = allValidity;
            this.recheckAfter = recheckAfter;
            this.newestTimestamp = newestTimestamp;
            this.blobCreatedAt = blobCreatedAt;
            this.keyBytes = keyBytes;
            this.reserveBytes = reserveBytes;
            this.checksum = checksum;
        }

        static KeyBlobContent parse(int base, long length, KeyBoxByteBuffer buffer, BlobVerifier blobVerifier)
            throws IOException
        {
            verifyDigest(base, length, buffer, blobVerifier);

            int blobFlags = buffer.u16();
            long keyBlockOffset = buffer.u32();
            long keyBlockLength = buffer.u32();

            int keyNumber = buffer.u16();
            int keyInformationStructureSize = buffer.u16();

            List<KeyInformation> keyInformation = new ArrayList<KeyInformation>();
            for (int t = keyNumber - 1; t >= 0; t--)
            {
                keyInformation.add(KeyInformation.getInstance(buffer, keyInformationStructureSize, base));
            }

            int sizeOfSerialNumber = buffer.u16();
            byte[] serialNumber = buffer.bN(sizeOfSerialNumber);

            int numberOfUserIDs = buffer.u16();
            buffer.u16();

            List<UserID> userIds = new ArrayList<UserID>();
            long totalUserIdLength = 0;
            for (int t = numberOfUserIDs - 1; t >= 0; t--)
            {
                UserID userID = UserID.getInstance(buffer, base);
                // Bound the cumulative user-ID data by the blob length: each entry copies an
                // attacker-controlled slice of the blob, so an inflated user-ID count with each entry
                // pointing at (almost) the whole blob would otherwise retain ~bufferSize^2 bytes.
                totalUserIdLength += userID.getLengthOfUserId();
                if (totalUserIdLength > length)
                {
                    throw new IllegalStateException("userID data exceeds blob length");
                }
                userIds.add(userID);
            }

            int numberOfSignatures = buffer.u16();
            buffer.u16();

            List<Long> signatureExpirationTime = new ArrayList<Long>();
            for (int t = numberOfSignatures - 1; t >= 0; t--)
            {
                signatureExpirationTime.add(buffer.u32());
            }

            int assignedOwnerTrust = buffer.u8();
            int allValidity = buffer.u8();

            buffer.u16();
            long recheckAfter = buffer.u32();
            long newestTimestamp = buffer.u32();
            long blobCreatedAt = buffer.u32();

            long sizeOfReservedSpace = buffer.u32();
            if (sizeOfReservedSpace > buffer.remaining())
            {
                throw new IllegalStateException("sizeOfReservedSpace exceeds content remaining in buffer");
            }

            byte[] reserveData = buffer.bN((int)sizeOfReservedSpace);
            byte[] keyData = buffer.rangeOf(
                (int)(base + keyBlockOffset),
                (int)(base + keyBlockOffset + keyBlockLength));

            int dataSize = (int)(length - (buffer.position() - base) - 20);
            buffer.bN(dataSize);

            byte[] checksum = buffer.rangeOf((int)(base + length - 20), (int)(base + length));
            buffer.consume(checksum.length);

            return new KeyBlobContent(blobFlags, keyNumber, keyInformation, serialNumber,
                numberOfUserIDs, userIds, numberOfSignatures, signatureExpirationTime,
                assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt,
                keyData, reserveData, checksum);
        }
    }

    public int getBlobFlags()
    {
        return blobFlags;
    }

    public int getKeyNumber()
    {
        return keyNumber;
    }

    public List<KeyInformation> getKeyInformation()
    {
        return keyInformation;
    }

    public byte[] getSerialNumber()
    {
        return serialNumber;
    }

    public int getNumberOfUserIDs()
    {
        return numberOfUserIDs;
    }

    public List<UserID> getUserIds()
    {
        return userIds;
    }

    public int getNumberOfSignatures()
    {
        return numberOfSignatures;
    }


    public List<Long> getExpirationTime()
    {
        return expirationTime;
    }

    public int getAssignedOwnerTrust()
    {
        return assignedOwnerTrust;
    }

    public int getAllValidity()
    {
        return allValidity;
    }

    public long getRecheckAfter()
    {
        return recheckAfter;
    }

    public long getNewestTimestamp()
    {
        return newestTimestamp;
    }

    public long getBlobCreatedAt()
    {
        return blobCreatedAt;
    }

    public byte[] getKeyBytes()
    {
        return keyBytes;
    }

    public byte[] getReserveBytes()
    {
        return reserveBytes;
    }

    public byte[] getChecksum()
    {
        return checksum;
    }
}
