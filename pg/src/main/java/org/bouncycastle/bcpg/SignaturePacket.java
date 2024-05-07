package org.bouncycastle.bcpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * generic signature packet
 */
public class SignaturePacket
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    public static final int VERSION_2 = 2;
    public static final int VERSION_3 = 3;
    public static final int VERSION_4 = 4;  // https://datatracker.ietf.org/doc/rfc4880/
    public static final int VERSION_5 = 5;  // https://datatracker.ietf.org/doc/draft-koch-librepgp/
    public static final int VERSION_6 = 6;  // https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/

    private int                    version;
    private int                    signatureType;
    private long                   creationTime;
    private long                   keyID;
    private int                    keyAlgorithm;
    private int                    hashAlgorithm;
    private MPInteger[]            signature;
    private byte[]                 fingerPrint;
    private SignatureSubpacket[]   hashedData;
    private SignatureSubpacket[]   unhashedData;
    private byte[]                 signatureEncoding;
    private byte[]                 salt; // v6 only

    SignaturePacket(
            BCPGInputStream    in)
            throws IOException
    {
        this(in, false);
    }

    SignaturePacket(
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {
        super(SIGNATURE, newPacketFormat);

        version = in.read();
        switch (version)
        {
            case VERSION_2:
            case VERSION_3:
                parseV2_V3(in);
                break;
            case VERSION_4:
            case VERSION_5:
                parseV4_V5(in);
                break;
            case VERSION_6:
                parseV6(in);
                break;
            default:
                Streams.drain(in);
                throw new UnsupportedPacketVersionException("unsupported version: " + version);
        }
    }

    /**
     * Parse a version 2 or version 3 signature.
     * @param in input stream which already skipped over the version number
     * @throws IOException if the packet is malformed
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-5.2.2">
     *     Version 3 packet format</a>
     */
    private void parseV2_V3(BCPGInputStream in)
        throws IOException
    {
        int    l = in.read(); // length l MUST be 5

        signatureType = in.read();
        creationTime = StreamUtil.readTime(in);

        keyID = StreamUtil.readKeyID(in);
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        // left 16 bits of the signed hash value
        fingerPrint = new byte[2];
        in.readFully(fingerPrint);

        parseSignature(in);
    }

    /**
     * Parse a version 4 or version 5 signature.
     * The difference between version 4 and 5 is that a version 5 signature contains additional metadata.
     * @param in input stream which already skipped over the version number
     * @throws IOException if the packet is malformed
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-5.2.3">
     *     Version 4 packet format</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-version-4-and-5-signature-p">
     *     Version 5 packet format</a>
     */
    private void parseV4_V5(BCPGInputStream in)
            throws IOException
    {
        signatureType = in.read();
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        parseSubpackets(in);

        // left 16 bits of the signed hash value
        fingerPrint = new byte[2];
        in.readFully(fingerPrint);

        parseSignature(in);
    }

    /**
     * Parse a version 6 signature.
     * Version 6 signatures do use 4 octet subpacket area length descriptors and contain an additional salt value
     * (which may or may not be of size 0, librepgp and crypto-refresh are in disagreement here).
     * @param in input stream which already skipped over the version number
     * @throws IOException if the packet is malformed
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-4-and-6-signature-p">
     *     Version 6 packet format</a>
     */
    private void parseV6(BCPGInputStream in)
            throws IOException
    {
        signatureType = in.read();
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        parseSubpackets(in);

        // left 16 bits of the signed hash value
        fingerPrint = new byte[2];
        in.readFully(fingerPrint);

        int saltSize = in.read();
        salt = new byte[saltSize];
        in.readFully(salt);

        parseSignature(in);
    }

    /**
     * Parse the hashed and unhashed signature subpacket areas of the signature.
     * Version 4 and 5 signature encode the area length using 2 octets, while version 6 uses 4 octet lengths instead.
     *
     * @param in input stream which skipped to after the hash algorithm octet
     * @throws IOException if the packet is malformed
     */
    private void parseSubpackets(BCPGInputStream in)
            throws IOException
    {
        int hashedLength;
        if (version == 6)
        {
            hashedLength = StreamUtil.read4OctetLength(in);
        }
        else
        {
            hashedLength = StreamUtil.read2OctetLength(in);
        }
        byte[]    hashed = new byte[hashedLength];

        in.readFully(hashed);

        //
        // read the signature sub packet data.
        //
        SignatureSubpacket    sub;
        SignatureSubpacketInputStream    sIn = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(hashed));

        Vector<SignatureSubpacket>    vec = new Vector<SignatureSubpacket>();
        while ((sub = sIn.readPacket()) != null)
        {
            vec.addElement(sub);
        }

        hashedData = new SignatureSubpacket[vec.size()];

        for (int i = 0; i != hashedData.length; i++)
        {
            SignatureSubpacket    p = vec.elementAt(i);
            if (p instanceof IssuerKeyID)
            {
                keyID = ((IssuerKeyID)p).getKeyID();
            }
            else if (p instanceof SignatureCreationTime)
            {
                creationTime = ((SignatureCreationTime)p).getTime().getTime();
            }

            hashedData[i] = p;
        }

        int unhashedLength;
        if (version == VERSION_6)
        {
            unhashedLength = StreamUtil.read4OctetLength(in);
        }
        else
        {
            unhashedLength = StreamUtil.read2OctetLength(in);
        }
        byte[]    unhashed = new byte[unhashedLength];

        in.readFully(unhashed);

        sIn = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(unhashed));

        vec.removeAllElements();
        while ((sub = sIn.readPacket()) != null)
        {
            vec.addElement(sub);
        }

        unhashedData = new SignatureSubpacket[vec.size()];

        for (int i = 0; i != unhashedData.length; i++)
        {
            SignatureSubpacket    p = vec.elementAt(i);
            if (p instanceof IssuerKeyID)
            {
                keyID = ((IssuerKeyID)p).getKeyID();
            }

            unhashedData[i] = p;
        }
    }

    /**
     * Parse the algorithm-specific signature encoding.
     * Ed25519 and Ed448 do not populate the signature MPInteger field, but instead read the raw signature to
     * signatureEncoding directly.
     *
     * @param in input stream which skipped the head of the signature
     * @throws IOException if the packet is malformed
     */
    private void parseSignature(BCPGInputStream in)
            throws IOException
    {
        switch (keyAlgorithm)
        {
            case RSA_GENERAL:
            case RSA_SIGN:
                MPInteger    v = new MPInteger(in);

                signature = new MPInteger[1];
                signature[0] = v;
                break;
            case DSA:
                MPInteger    r = new MPInteger(in);
                MPInteger    s = new MPInteger(in);

                signature = new MPInteger[2];
                signature[0] = r;
                signature[1] = s;
                break;
            case ELGAMAL_ENCRYPT: // yep, this really does happen sometimes.
            case ELGAMAL_GENERAL:
                MPInteger       p = new MPInteger(in);
                MPInteger       g = new MPInteger(in);
                MPInteger       y = new MPInteger(in);

                signature = new MPInteger[3];
                signature[0] = p;
                signature[1] = g;
                signature[2] = y;
                break;
            case Ed448:
                signatureEncoding = new byte[org.bouncycastle.math.ec.rfc8032.Ed448.SIGNATURE_SIZE];
                in.readFully(signatureEncoding);
                break;
            case Ed25519:
                signatureEncoding = new byte[org.bouncycastle.math.ec.rfc8032.Ed25519.SIGNATURE_SIZE];
                in.readFully(signatureEncoding);
                break;
            case ECDSA:
            case EDDSA_LEGACY:

                MPInteger    ecR = new MPInteger(in);
                MPInteger    ecS = new MPInteger(in);

                signature = new MPInteger[2];
                signature[0] = ecR;
                signature[1] = ecS;
                break;
            default:
                if (keyAlgorithm >= PublicKeyAlgorithmTags.EXPERIMENTAL_1 && keyAlgorithm <= PublicKeyAlgorithmTags.EXPERIMENTAL_11)
                {
                    signature = null;
                    signatureEncoding = Streams.readAll(in);
                }
                else
                {
                    throw new IOException("unknown signature key algorithm: " + keyAlgorithm);
                }
        }
    }

    /**
     * Generate a version 4 signature packet.
     *
     * @param signatureType
     * @param keyAlgorithm
     * @param hashAlgorithm
     * @param hashedData
     * @param unhashedData
     * @param fingerPrint
     * @param signature
     */
    public SignaturePacket(
        int                     signatureType,
        long                    keyID,
        int                     keyAlgorithm,
        int                     hashAlgorithm,
        SignatureSubpacket[]    hashedData,
        SignatureSubpacket[]    unhashedData,
        byte[]                  fingerPrint,
        MPInteger[]             signature)
    {
        this(4, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature);
    }

    /**
     * Generate a version 2/3 signature packet.
     *
     * @param signatureType
     * @param keyAlgorithm
     * @param hashAlgorithm
     * @param fingerPrint
     * @param signature
     */
    public SignaturePacket(
        int                     version,
        int                     signatureType,
        long                    keyID,
        int                     keyAlgorithm,
        int                     hashAlgorithm,
        long                    creationTime,
        byte[]                  fingerPrint,
        MPInteger[]             signature)
    {
        this(version, signatureType, keyID, keyAlgorithm, hashAlgorithm, null, null, fingerPrint, signature);

        this.creationTime = creationTime;
    }

    public SignaturePacket(
        int                     version,
        int                     signatureType,
        long                    keyID,
        int                     keyAlgorithm,
        int                     hashAlgorithm,
        SignatureSubpacket[]    hashedData,
        SignatureSubpacket[]    unhashedData,
        byte[]                  fingerPrint,
        MPInteger[]             signature)
    {
        super(SIGNATURE);

        this.version = version;
        this.signatureType = signatureType;
        this.keyID = keyID;
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.hashedData = hashedData;
        this.unhashedData = unhashedData;
        this.fingerPrint = fingerPrint;
        this.signature = signature;

        if (hashedData != null)
        {
            setCreationTime();
        }
    }

    public SignaturePacket(
            int                     version,
            int                     signatureType,
            long                    keyID,
            int                     keyAlgorithm,
            int                     hashAlgorithm,
            SignatureSubpacket[]    hashedData,
            SignatureSubpacket[]    unhashedData,
            byte[]                  fingerPrint,
            byte[]                  signatureEncoding)
    {
        super(SIGNATURE);

        this.version = version;
        this.signatureType = signatureType;
        this.keyID = keyID;
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.hashedData = hashedData;
        this.unhashedData = unhashedData;
        this.fingerPrint = fingerPrint;
        this.signatureEncoding = Arrays.clone(signatureEncoding);
        if (hashedData != null)
        {
            setCreationTime();
        }
    }

    /**
     * get the version number
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * return the signature type.
     */
    public int getSignatureType()
    {
        return signatureType;
    }

    /**
     * return the keyID
     * @return the keyID that created the signature.
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return the signature's fingerprint.
     * @return fingerprint (digest prefix) of the signature
     */
    public byte[] getFingerPrint()
    {
        return Arrays.clone(fingerPrint);
    }

    /**
     * Return the signature's salt.
     * Only for v6 signatures.
     * @return salt
     */
    public byte[] getSalt()
    {
        return salt;
    }

    /**
     * return the signature trailer that must be included with the data
     * to reconstruct the signature
     *
     * @return byte[]
     */
    public byte[] getSignatureTrailer()
    {
        byte[]    trailer = null;

        if (version == 3 || version == 2)
        {
            trailer = new byte[5];

            long    time = creationTime / 1000;

            trailer[0] = (byte)signatureType;
            trailer[1] = (byte)(time >> 24);
            trailer[2] = (byte)(time >> 16);
            trailer[3] = (byte)(time >> 8);
            trailer[4] = (byte)(time);
        }
        else
        {
            ByteArrayOutputStream    sOut = new ByteArrayOutputStream();
            SignatureSubpacket[]     hashed = this.getHashedSubPackets();
            try
            {
                sOut.write((byte)this.getVersion());
                sOut.write((byte)this.getSignatureType());
                sOut.write((byte)this.getKeyAlgorithm());
                sOut.write((byte)this.getHashAlgorithm());

                ByteArrayOutputStream    hOut = new ByteArrayOutputStream();


                for (int i = 0; i != hashed.length; i++)
                {
                    hashed[i].encode(hOut);
                }

                byte[]                   data = hOut.toByteArray();
                StreamUtil.write2OctetLength(sOut, data.length);
                sOut.write(data);

                byte[]    hData = sOut.toByteArray();

                sOut.write((byte)this.getVersion());
                sOut.write((byte)0xff);
                StreamUtil.write4OctetLength(sOut, hData.length);
            }
            catch (IOException e)
            {
                throw new RuntimeException("exception generating trailer: " + e);
            }

            trailer = sOut.toByteArray();
        }

        return trailer;
    }

    /**
     * return the encryption algorithm tag
     */
    public int getKeyAlgorithm()
    {
        return keyAlgorithm;
    }

    /**
     * return the hashAlgorithm tag
     */
    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    /**
     * return the signature as a set of integers - note this is normalised to be the
     * ASN.1 encoding of what appears in the signature packet.
     * Note, that Ed25519 and Ed448 returns null, as the raw signature is stored in signatureEncoding only.
     * For those, use {@link #getSignatureBytes()} instead.
     */
    public MPInteger[] getSignature()
    {
        return signature;
    }

    /**
     * Return the byte encoding of the signature section.
     * @return uninterpreted signature bytes.
     */
    public byte[] getSignatureBytes()
    {
        if (signatureEncoding != null)
        {
            return Arrays.clone(signatureEncoding);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            BCPGOutputStream bcOut = new BCPGOutputStream(bOut);
            for (int i = 0; i != signature.length; i++)
            {
                bcOut.writeObject(signature[i]);
            }
            bcOut.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException("internal error: " + e);
        }

        return bOut.toByteArray();
    }

    public SignatureSubpacket[] getHashedSubPackets()
    {
        return hashedData;
    }

    public SignatureSubpacket[] getUnhashedSubPackets()
    {
        return unhashedData;
    }

    /**
     * Return the creation time of the signature in milli-seconds.
     *
     * @return the creation time in millis
     */
    public long getCreationTime()
    {
        return creationTime;
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);

        pOut.write(version);

        if (version == VERSION_3 || version == VERSION_2)
        {
            pOut.write(5); // the length of the next block

            long    time = creationTime / 1000;

            pOut.write(signatureType);
            StreamUtil.writeTime(pOut, time);

            StreamUtil.writeKeyID(pOut, keyID);

            pOut.write(keyAlgorithm);
            pOut.write(hashAlgorithm);
        }
        else if (version == VERSION_4 || version == VERSION_5 || version == VERSION_6)
        {
            pOut.write(signatureType);
            pOut.write(keyAlgorithm);
            pOut.write(hashAlgorithm);

            ByteArrayOutputStream    sOut = new ByteArrayOutputStream();

            for (int i = 0; i != hashedData.length; i++)
            {
                hashedData[i].encode(sOut);
            }

            byte[]                   data = sOut.toByteArray();

            if (version == VERSION_6)
            {
                StreamUtil.write4OctetLength(pOut, data.length);
            }
            else
            {
                StreamUtil.write2OctetLength(pOut, data.length);
            }
            pOut.write(data);

            sOut.reset();

            for (int i = 0; i != unhashedData.length; i++)
            {
                unhashedData[i].encode(sOut);
            }

            data = sOut.toByteArray();

            if (version == VERSION_6)
            {
                StreamUtil.write4OctetLength(pOut, data.length);
            }
            else
            {
                StreamUtil.write2OctetLength(pOut, data.length);
            }
            pOut.write(data);
        }
        else
        {
            throw new IOException("unknown version: " + version);
        }

        pOut.write(fingerPrint);

        if (version == VERSION_6)
        {
            pOut.write(salt.length);
            pOut.write(salt);
        }

        if (signature != null)
        {
            for (int i = 0; i != signature.length; i++)
            {
                pOut.writeObject(signature[i]);
            }
        }
        else
        {
            pOut.write(signatureEncoding);
        }

        pOut.close();

        out.writePacket(hasNewPacketFormat(), SIGNATURE, bOut.toByteArray());
    }

    private void setCreationTime()
    {
        for (int i = 0; i != hashedData.length; i++)
        {
            if (hashedData[i] instanceof SignatureCreationTime)
            {
                creationTime = ((SignatureCreationTime)hashedData[i]).getTime().getTime();
                break;
            }
        }
    }

    public static SignaturePacket fromByteArray(byte[] data)
        throws IOException
    {
        BCPGInputStream in = new BCPGInputStream(new ByteArrayInputStream(data));

        return new SignaturePacket(in);
    }
}
