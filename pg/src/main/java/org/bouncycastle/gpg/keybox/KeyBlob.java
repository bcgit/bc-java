package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.Arrays;

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

    static void verifyDigest(int base, long length, KeyBoxByteBuffer buffer)
        throws IOException
    {
        byte[] blobData = buffer.rangeOf(base, (int)(base + length - 20));
        SHA1Digest sha1Digest = new SHA1Digest();
        sha1Digest.update(blobData, 0, blobData.length);
        byte[] calculatedDigest = new byte[sha1Digest.getDigestSize()];
        sha1Digest.doFinal(calculatedDigest, 0);

        byte[] blobDigest = buffer.rangeOf((int)(base + length - 20), (int)(base + length));

        if (!Arrays.areEqual(calculatedDigest, blobDigest))
        {
            //
            // Special case for old key boxes that used MD5.
            //

            /*
             http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=kbx/keybox-blob.c;hb=HEAD#l129
             SHA-1 checksum (useful for KS syncronisation?)
             Note, that KBX versions before GnuPG 2.1 used an MD5
             checksum.  However it was only created but never checked.
             Thus we do not expect problems if we switch to SHA-1.  If
             the checksum fails and the first 4 bytes are zero, we can
             try again with MD5.  SHA-1 has the advantage that it is
             faster on CPUs with dedicated SHA-1 support.
            */

            if (blobDigest[0] == 0 && blobDigest[1] == 0 && blobDigest[2] == 0 && blobDigest[3] == 0)
            {
                MD5Digest md5Digest = new MD5Digest();
                md5Digest.update(blobData, 0, blobData.length);
                calculatedDigest = new byte[md5Digest.getDigestSize()];
                md5Digest.doFinal(calculatedDigest, 0);
                boolean ok = true;
                for (int t = 4; t < blobDigest.length; t++)
                {
                    if (calculatedDigest[t - 4] != blobDigest[t])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    return;
                }
            }
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
