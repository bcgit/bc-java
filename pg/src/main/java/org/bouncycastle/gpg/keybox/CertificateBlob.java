package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * A PGP blob holds key material.
 */
public class CertificateBlob
    extends KeyBlob
{
    private CertificateBlob(int base, long length,
                            BlobType type,
                            int version,
                            int blobFlags,
                            long keyBlockOffset,
                            long keyBlockLength,
                            int keyNumber,
                            int additionalKeyInfoSize,
                            List<KeyInformation> keyInformation,
                            int sizeOfSerialNumber,
                            byte[] serialNumber,
                            int numberOfUserIDs,
                            int sizeOfUserIdInformation,
                            List<UserID> userIds,
                            int numberOfSignatures,
                            int sizeOfSignatureInfo,
                            List<Long> expirationTime,
                            int assignedOwnerTrust,
                            int allValidity,
                            long recheckAfter,
                            long newestTimestamp,
                            long blobCreatedAt,
                            long sizeOfReservedSpace,
                            byte[] keyBytes,
                            byte[] reserveBytes,
                            byte[] sha1Checksum)
    {
        super(base, length, type, version, blobFlags, keyBlockOffset, keyBlockLength, keyNumber, additionalKeyInfoSize,
       keyInformation, sizeOfSerialNumber, serialNumber, numberOfUserIDs, sizeOfUserIdInformation, userIds, numberOfSignatures,
       sizeOfSignatureInfo, expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt,
       sizeOfReservedSpace, keyBytes, reserveBytes, sha1Checksum);
    }


    static Blob parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer, KeyFingerPrintCalculator fingerPrintCalculator)
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
        verifyDigest(base, length, buffer);


        int blobFlags = buffer.u16(); //  u16  Blob flags
        long keyBlockOffset = buffer.u32();   //  u32  offset to the OpenPGP keyblock or X509 DER encoded certificate
        long keyBlockLength = buffer.u32(); // u32  and its length

        int keyNumber = buffer.u16(); //  u16  number of keys (at least 1!) [X509: always 1]


        // This value defines the length of the space reserved for the AdditionalKeyInformation
        int keyInformationStructureSize = buffer.u16(); // u16  size of additional key information

        //
        // Load the additional key information.
        //
        List<KeyInformation> keyInformation = new ArrayList<KeyInformation> ();

        for (int t = keyNumber - 1; t >= 0; t--)
        {
            keyInformation.add(KeyInformation.getInstance(buffer, keyInformationStructureSize, base));
        }

        int sizeOfSerialNumber = buffer.u16(); // size of serialnumber(may be zero)

        byte[] serialNumber = new byte[sizeOfSerialNumber];
        buffer.bN(serialNumber); // n  u16 (see above) bytes of serial number

        int numberOfUserIDs = buffer.u16(); //  u16  number of user IDs
        int sizeOfUserIdInformation = buffer.u16(); // size of additional user ID information

        //
        // User IDS.
        //
        List<UserID> userIds = new ArrayList<UserID>();
        for (int t = numberOfUserIDs - 1; t >= 0; t--)
        {
            userIds.add(UserID.getInstance(buffer, base));
        }

        int numberOfSignatures = buffer.u16();
        int sizeOfSignatureInfo = buffer.u16();


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


        // Arbitrary reserved space, that may hold X509 V3 certificate IDs.!
        byte[] reserveData = new byte[(int)sizeOfReservedSpace]; // Reserved space of size NRES for future use.
        buffer.bN(reserveData);


        //
        // Keyblock
        //

        byte[] keyData = buffer.rangeOf(
            (int)(base + keyBlockOffset),
            (int)(base + keyBlockOffset + keyBlockLength)); // Defined near top of structure..


        //
        // Reserved space not covered by checksum.
        //
        int dataSize = (int)(length - (buffer.position() - base) - 20);
        byte[] data = new byte[dataSize];
        buffer.bN(data);


        byte[] sha1Checksum = buffer.rangeOf((int)(base + length - 20), (int)(base + length));
        buffer.bN(sha1Checksum);

        return new CertificateBlob(base, length,
            type,
            version,
            blobFlags,
            keyBlockOffset,
            keyBlockLength,
            keyNumber,
            keyInformationStructureSize,
            keyInformation,
            sizeOfSerialNumber,
            serialNumber,
            numberOfUserIDs,
            sizeOfUserIdInformation,
            userIds,
            numberOfSignatures,
            sizeOfSignatureInfo,
            signatureExpirationTime,
            assignedOwnerTrust,
            allValidity,
            recheckAfter,
            newestTimestamp,
            blobCreatedAt,
            sizeOfReservedSpace,
            keyData, reserveData, sha1Checksum);
    }

    public byte[] getEncodedCertificate()
        throws IOException, CertificateException
    {
        return getKeyBytes();
    }
}
