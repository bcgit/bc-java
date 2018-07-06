package org.bouncycastle.gpg.keybox;

import java.io.IOException;
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
