package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * A PGP blob holds key material.
 */
public class PublicKeyRingBlob
    extends KeyBlob
{
    private final KeyFingerPrintCalculator fingerPrintCalculator;

    private PublicKeyRingBlob(int base, long length,
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
                              byte[] sha1Checksum,
                              KeyFingerPrintCalculator fingerPrintCalculator)
    {
        super(base, length, type, version, blobFlags, keyNumber,
            keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures,
            expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt,
            keyBytes, reserveBytes, sha1Checksum);
        this.fingerPrintCalculator = fingerPrintCalculator;
    }


    static Blob parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {

        //
        // u32  Length of this blob (including these 4 bytes)
        // byte Blob type
        //             2 = OpenPGP
        //             3 = X509
        //  byte Version number of this blob type
        //             1 = The only defined value
        //


        //
        // Take checksum first.
        //
        verifyDigest(base, length, buffer, blobVerifier);


        int blobFlags = buffer.u16(); //  u16  Blob flags
        long keyBlockOffset = buffer.u32();   //  u32  offset to the OpenPGP keyblock or X509 DER encoded certificate
        long keyBlockLength = buffer.u32(); // u32  and its length

        int keyNumber = buffer.u16(); //  u16  number of keys (at least 1!) [X509: always 1]


        // This value defines the length of the space reserved for the AdditionalKeyInformation
        int keyInformationStructureSize = buffer.u16(); // u16  size of additional key information

        //
        // Load the additional key information.
        //
        ArrayList<KeyInformation> keyInformation = new ArrayList<KeyInformation>();

        for (int t = keyNumber - 1; t >= 0; t--)
        {
            keyInformation.add(KeyInformation.getInstance(buffer, keyInformationStructureSize, base));
        }

        int sizeOfSerialNumber = buffer.u16(); // size of serialnumber(may be zero)
        byte[] serialNumber = buffer.bN(sizeOfSerialNumber); // n  u16 (see above) bytes of serial number

        int numberOfUserIDs = buffer.u16(); //  u16  number of user IDs
        buffer.u16(); // size of user ID information

        //
        // User IDS.
        //
        ArrayList<UserID> userIds = new ArrayList<UserID>();
        for (int t = numberOfUserIDs - 1; t >= 0; t--)
        {
            userIds.add(UserID.getInstance(buffer, base));
        }

        int numberOfSignatures = buffer.u16();
        buffer.u16(); // Size of signature info.


        List<Long> signatureExpirationTime = new ArrayList<Long>();
        for (int t = numberOfSignatures - 1; t >= 0; t--)
        {
            signatureExpirationTime.add(buffer.u32());
        }

        int assignedOwnerTrust = buffer.u8(); //  din.read();
        int allValidity = buffer.u8();

        buffer.u16(); // RFU
        long recheckAfter = buffer.u32();
        long newestTimestamp = buffer.u32();
        long blobCreatedAt = buffer.u32();

        long sizeOfReservedSpace = buffer.u32();

        if (sizeOfReservedSpace > buffer.remaining())
        {
            throw new IllegalStateException("sizeOfReservedSpace exceeds content remaining in buffer");
        }

        // Arbitrary reserved space, that may hold X509 V3 certificate IDs.!
        byte[] reserveData = buffer.bN((int)sizeOfReservedSpace); // Reserved space of size NRES for future use.

        //
        // Key block
        //

        byte[] keyData = buffer.rangeOf(
            (int)(base + keyBlockOffset),
            (int)(base + keyBlockOffset + keyBlockLength)); // Defined near top of structure..


        //
        // Reserved space not covered by checksum.
        //
        int dataSize = (int)(length - (buffer.position() - base) - 20);
        //byte[] data = new byte[dataSize];
        byte[] data = buffer.bN(dataSize);


        byte[] checksum = buffer.rangeOf((int)(base + length - 20), (int)(base + length));
        buffer.consume(checksum.length);

        return new PublicKeyRingBlob(base, length,
            type,
            version,
            blobFlags,
            keyNumber,
            keyInformation,
            serialNumber,
            numberOfUserIDs,
            userIds,
            numberOfSignatures,
            signatureExpirationTime,
            assignedOwnerTrust,
            allValidity,
            recheckAfter,
            newestTimestamp,
            blobCreatedAt,
            keyData, reserveData, checksum, fingerPrintCalculator);
    }

    /**
     * Return the gpg public key ring from the key box blob.
     *
     * @return A new PGPPublicKeyRing based on the blobs raw data.
     * @throws IOException if the data cannot be parsed.
     * @throws IllegalStateException if the blob is not BlobType.OPEN_PGP_BLOB
     */
    public PGPPublicKeyRing getPGPPublicKeyRing()
        throws IOException
    {
        if (this.type == BlobType.OPEN_PGP_BLOB)
        {
            return new PGPPublicKeyRing(
                getKeyBytes(), fingerPrintCalculator);
        }

        throw new IllegalStateException("Blob is not PGP blob, it is " + type.name());
    }
}
