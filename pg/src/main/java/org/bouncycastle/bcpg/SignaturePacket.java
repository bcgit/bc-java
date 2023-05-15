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
    public static final int VERSION_3 = 3;
    public static final int VERSION_4 = 4;
    public static final int VERSION_5 = 5;
    public static final int VERSION_6 = 6;

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
    private byte[] salt = null; // v6 only
    
    SignaturePacket(
        BCPGInputStream    in)
        throws IOException
    {
        version = in.read();

        // TODO: Version 2 is not specified. Clarify?
        if (version == VERSION_3 || version == 2)
        {
            readVersion2_3Packet(in);
        }
        else if (version == VERSION_4 || version == VERSION_5)
        {
            readVersion4_5Packet(in);
        }
        else if (version == VERSION_6)
        {
            readVersion6Packet(in);
        }
        else
        {
            Streams.drain(in);
            throw new UnsupportedPacketVersionException("unsupported version: " + version);
        }
    }

    private void readVersion2_3Packet(BCPGInputStream in) throws IOException {
        int    l = in.read();

        signatureType = in.read();
        creationTime = (((long) in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read()) * 1000;
        keyID |= (long) in.read() << 56;
        keyID |= (long) in.read() << 48;
        keyID |= (long) in.read() << 40;
        keyID |= (long) in.read() << 32;
        keyID |= (long) in.read() << 24;
        keyID |= (long) in.read() << 16;
        keyID |= (long) in.read() << 8;
        keyID |= in.read();
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        // 2 byte fp
        readFingerprint(in);

        readSignature(in);
    }

    private void readVersion4_5Packet(BCPGInputStream in) throws IOException {
        signatureType = in.read();
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        hashedData = readSubpackets(in, true);
        unhashedData = readSubpackets(in, false);

        // 2 byte fp
        readFingerprint(in);
        readSignature(in);
    }


    private void readVersion6Packet(BCPGInputStream in) throws IOException {
        signatureType = in.read();
        keyAlgorithm = in.read();
        hashAlgorithm = in.read();

        hashedData = readSubpackets(in, true);
        unhashedData = readSubpackets(in, false);

        // 2 byte fp
        readFingerprint(in);

        readSalt(in);

        readSignature(in);
    }

    private SignatureSubpacket[] readSubpackets(BCPGInputStream in, boolean isHashed)
            throws IOException
    {
        int       length = readLength(in);
        byte[]    data = new byte[length];

        in.readFully(data);

        //
        // read the signature sub packet data.
        //
        SignatureSubpacket    sub;
        SignatureSubpacketInputStream    sIn = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(data));

        Vector<SignatureSubpacket>    v = new Vector<SignatureSubpacket>();
        while ((sub = sIn.readPacket()) != null)
        {
            v.addElement(sub);
        }

        SignatureSubpacket[] subpackets = new SignatureSubpacket[v.size()];

        for (int i = 0; i != subpackets.length; i++)
        {
            SignatureSubpacket    p = v.elementAt(i);
            if (isHashed)
            {
                if (p instanceof IssuerKeyID)
                {
                    keyID = ((IssuerKeyID) p).getKeyID();
                }
                else if (p instanceof SignatureCreationTime)
                {
                    creationTime = ((SignatureCreationTime) p).getTime().getTime();
                }
            }
            else
            {
                if (p instanceof IssuerKeyID && keyID == 0)
                {
                    keyID = ((IssuerKeyID) p).getKeyID();
                }
            }

            subpackets[i] = p;
        }

        return subpackets;
    }

    private void readFingerprint(BCPGInputStream in) throws IOException {
        fingerPrint = new byte[2];
        in.readFully(fingerPrint);
    }

    private void readSalt(BCPGInputStream in) throws IOException {
        int saltSize = in.read();

        int expectedSaltSize = getSaltSize(hashAlgorithm);
        if (expectedSaltSize != -1 && saltSize != getSaltSize(hashAlgorithm)) {
            throw new IOException("Salt length mismatch. Expected " + expectedSaltSize + " bytes, but signature indicates " + saltSize);
        }

        salt = new byte[saltSize];
        in.readFully(salt);
    }

    private void readSignature(BCPGInputStream in) throws IOException {
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
            case ECDSA:
            case EDDSA_LEGACY:
                MPInteger    ecR = new MPInteger(in);
                MPInteger    ecS = new MPInteger(in);

                signature = new MPInteger[2];
                signature[0] = ecR;
                signature[1] = ecS;
                break;
            case Ed25519:
                signature = null;
                signatureEncoding = new byte[64];
                in.readFully(signatureEncoding);
                break;
            case Ed448:
                signature = null;
                signatureEncoding = new byte[114];
                in.readFully(signatureEncoding);
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

    private int readLength(BCPGInputStream in) throws IOException {
        int hashedLength;
        if (version == VERSION_4)
        {
            hashedLength = (in.read() << 8) | in.read();
        }
        else
        {
            hashedLength = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
        }
        return hashedLength;
    }

    static int getSaltSize(int hashAlgorithm)
    {
        switch (hashAlgorithm) {
            case HashAlgorithmTags.SHA256:
            case HashAlgorithmTags.SHA224:
            case HashAlgorithmTags.SHA3_256:
                return 16;
            case HashAlgorithmTags.SHA384:
                return 24;
            case HashAlgorithmTags.SHA512:
            case HashAlgorithmTags.SHA3_512:
                return 32;
            default:
                return -1;
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
     * return the signature trailer that must be included with the data
     * to reconstruct the signature
     * 
     * @return byte[]
     */
    public byte[] getSignatureTrailer()
    {
        byte[]    trailer = null;
        
        if (version == VERSION_3 || version == 2)
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
        
            try
            {
                sOut.write((byte)this.getVersion());
                sOut.write((byte)this.getSignatureType());
                sOut.write((byte)this.getKeyAlgorithm());
                sOut.write((byte)this.getHashAlgorithm());
            
                ByteArrayOutputStream    hOut = new ByteArrayOutputStream();
                SignatureSubpacket[]     hashed = this.getHashedSubPackets();
            
                for (int i = 0; i != hashed.length; i++)
                {
                    hashed[i].encode(hOut);
                }
                
                byte[]                   data = hOut.toByteArray();

                if (version == VERSION_6)
                {
                    sOut.write((byte)(data.length >> 24));
                    sOut.write((byte)(data.length >> 16));
                }
                sOut.write((byte)(data.length >> 8));
                sOut.write((byte)data.length);
                sOut.write(data);
            
                byte[]    hData = sOut.toByteArray();
            
                sOut.write((byte)this.getVersion());
                sOut.write((byte)0xff);
                sOut.write((byte)(hData.length>> 24));
                sOut.write((byte)(hData.length >> 16));
                sOut.write((byte)(hData.length >> 8));
                sOut.write((byte)(hData.length));
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
        
        if (version == VERSION_3 || version == 2)
        {
            pOut.write(5); // the length of the next block
            
            long    time = creationTime / 1000;
            
            pOut.write(signatureType);
            pOut.write((byte)(time >> 24));
            pOut.write((byte)(time >> 16));
            pOut.write((byte)(time >> 8));
            pOut.write((byte)time);

            pOut.write((byte)(keyID >> 56));
            pOut.write((byte)(keyID >> 48));
            pOut.write((byte)(keyID >> 40));
            pOut.write((byte)(keyID >> 32));
            pOut.write((byte)(keyID >> 24));
            pOut.write((byte)(keyID >> 16));
            pOut.write((byte)(keyID >> 8));
            pOut.write((byte)(keyID));
            
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
                pOut.write(data.length >> 24);
                pOut.write(data.length >> 16);
            }
            pOut.write(data.length >> 8);
            pOut.write(data.length);
            pOut.write(data);
            
            sOut.reset();
            
            for (int i = 0; i != unhashedData.length; i++)
            {
                unhashedData[i].encode(sOut);
            }
            
            data = sOut.toByteArray();

            if (version == VERSION_6)
            {
                pOut.write(data.length >> 24);
                pOut.write(data.length >> 16);
            }
            pOut.write(data.length >> 8);
            pOut.write(data.length);
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

        out.writePacket(SIGNATURE, bOut.toByteArray());
    }

    public byte[] getSalt() {
        return Arrays.clone(salt);
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
