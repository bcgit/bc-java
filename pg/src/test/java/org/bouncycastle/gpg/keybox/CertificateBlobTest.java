package org.bouncycastle.gpg.keybox;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Robustness test for {@link CertificateBlob#parseContent}: a malformed X509 keybox blob that
 * declares an attacker-controlled {@code sizeOfReservedSpace} larger than the bytes actually
 * remaining must be rejected with the same clean {@code IllegalStateException} that
 * {@link PublicKeyRingBlob} already throws.
 * <p>
 * The integrity digest verified up front by {@link KeyBlob#verifyDigest} is an unkeyed SHA-1/MD5
 * checksum, so a crafted .kbx can satisfy it before the length is read; this test models that
 * reachable state with a permissive {@link BlobVerifier} rather than recomputing a checksum.
 */
public class CertificateBlobTest
    extends SimpleTest
{
    private static final BlobVerifier ACCEPT_ALL = new BlobVerifier()
    {
        public boolean isMatched(byte[] blobData, byte[] blobDigest)
        {
            return true;
        }
    };

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new CertificateBlobTest());
    }

    public String getName()
    {
        return "CertificateBlob";
    }

    public void performTest()
        throws Exception
    {
        // The sizeOfReservedSpace guard (added to CertificateBlob for parity with PublicKeyRingBlob)
        // rejects an oversized reserved-space length with a descriptive IllegalStateException. With
        // KeyBoxByteBuffer.u32() now masking to unsigned, the guard covers the whole u32 range,
        // including values with bit 31 set that previously sign-extended to a negative long and
        // slipped past the '> remaining()' check down to bN.
        checkGuardRejects(0x7FFFFFFFL);
        checkGuardRejects(0xFFFFFFFFL);

        // The user-ID loop bounds its cumulative copied data by the blob length, defeating the
        // quadratic memory amplification of many entries each pointing at (almost) the whole blob.
        // Two 80-byte entries against a 100-byte blob exceed the bound and are rejected.
        checkUserIdDataBounded();
    }

    private void checkGuardRejects(long sizeOfReservedSpace)
        throws Exception
    {
        try
        {
            parseWithReservedSpace(sizeOfReservedSpace);
            fail("oversized sizeOfReservedSpace not rejected");
        }
        catch (IllegalStateException e)
        {
            isEquals("sizeOfReservedSpace exceeds content remaining in buffer", e.getMessage());
        }
    }

    private void checkUserIdDataBounded()
        throws Exception
    {
        KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(craftX509BlobWithUserIds(100, 2, 0, 80));
        buffer.position(6); // skip the u32 length + u8 type + u8 version that Blob.getInstance() consumes

        try
        {
            CertificateBlob.parseContent(0, 100, BlobType.X509_BLOB, 1, buffer, ACCEPT_ALL);
            fail("oversized total userID data not rejected");
        }
        catch (IllegalStateException e)
        {
            isEquals("userID data exceeds blob length", e.getMessage());
        }
    }

    private void parseWithReservedSpace(long sizeOfReservedSpace)
        throws Exception
    {
        KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(craftX509Blob(sizeOfReservedSpace));
        buffer.position(6); // skip the u32 length + u8 type + u8 version that Blob.getInstance() consumes
        CertificateBlob.parseContent(0, 60, BlobType.X509_BLOB, 1, buffer, ACCEPT_ALL);
    }

    /**
     * Build a 60-byte X509 blob whose key/serial/user-id/signature counts are all zero, so parsing
     * reaches the sizeOfReservedSpace field directly, set to the supplied (oversized) u32 value.
     */
    private static byte[] craftX509Blob(long sizeOfReservedSpace)
    {
        byte[] blob = new byte[60];

        putU32(blob, 0, 60);                                 // [0..3]   u32 length (parseContent uses the passed-in length)
        blob[4] = (byte)BlobType.X509_BLOB.getByteValue();  // [4]      blob type
        blob[5] = 1;                                         // [5]      version

        // [6..7]   u16 blobFlags                            (0)
        // [8..11]  u32 keyBlockOffset                       (0)
        // [12..15] u32 keyBlockLength                       (0)
        // [16..17] u16 keyNumber                            (0 -> no KeyInformation entries)
        // [18..19] u16 keyInformationStructureSize          (0)
        // [20..21] u16 sizeOfSerialNumber                   (0)
        // [22..23] u16 numberOfUserIDs                      (0 -> no UserID entries)
        // [24..25] u16 additional user id info size         (0)
        // [26..27] u16 numberOfSignatures                   (0 -> no signature entries)
        // [28..29] u16                                      (0)
        // [30]     u8  assignedOwnerTrust                   (0)
        // [31]     u8  allValidity                          (0)
        // [32..33] u16 RFU                                  (0)
        // [34..37] u32 recheckAfter                         (0)
        // [38..41] u32 newestTimestamp                      (0)
        // [42..45] u32 blobCreatedAt                        (0)
        putU32(blob, 46, sizeOfReservedSpace);              // [46..49] u32 sizeOfReservedSpace (attacker-controlled)

        return blob;
    }

    private static void putU32(byte[] b, int off, long v)
    {
        b[off] = (byte)(v >>> 24);
        b[off + 1] = (byte)(v >>> 16);
        b[off + 2] = (byte)(v >>> 8);
        b[off + 3] = (byte)v;
    }

    private static void putU16(byte[] b, int off, int v)
    {
        b[off] = (byte)(v >>> 8);
        b[off + 1] = (byte)v;
    }

    /**
     * Build an X509 blob carrying {@code numUserIds} UserID entries, each declaring the given
     * absolute offset and length, with every other count (keys, serial, signatures) zero, so
     * parsing runs straight into the user-ID loop.
     */
    private static byte[] craftX509BlobWithUserIds(int totalSize, int numUserIds, long offsetEach, long lengthEach)
    {
        byte[] blob = new byte[totalSize];

        putU32(blob, 0, totalSize);                         // [0..3]   u32 length
        blob[4] = (byte)BlobType.X509_BLOB.getByteValue();  // [4]      blob type
        blob[5] = 1;                                        // [5]      version
        // keyNumber [16..17], keyInformationStructureSize [18..19], sizeOfSerialNumber [20..21] all 0
        putU16(blob, 22, numUserIds);                       // [22..23] u16 numberOfUserIDs
        // [24..25] additional user id info size            (0)

        int p = 26;                                         // first UserID entry (12 bytes each)
        for (int i = 0; i < numUserIds; i++)
        {
            putU32(blob, p, offsetEach);     // offsetToUserId
            putU32(blob, p + 4, lengthEach); // lengthOfUserId
            putU16(blob, p + 8, 0);          // special user id flags
            blob[p + 10] = 0;                // validity
            blob[p + 11] = 0;                // reserved
            p += 12;
        }

        return blob;
    }
}
