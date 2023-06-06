package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * generic signature object
 */
public class OnePassSignaturePacket 
    extends ContainedPacket
{
    public static final int VERSION_3 = 3;
    public static final int VERSION_6 = 6;

    private final int  version;           // v3, v6
    private final int  sigType;           // v3, v6
    private final int  hashAlgorithm;     // v3, v6
    private final int  keyAlgorithm;      // v3, v6
    private final byte[] salt;            //     v6
    private final long keyID;             // v3
    private final byte[] keyFingerprint;  //     v6
    private final int isContaining;       // v3, v6
    
    OnePassSignaturePacket(
        BCPGInputStream    in)
        throws IOException
    {
        version = in.read();
        sigType = in.read();
        hashAlgorithm = in.read();
        keyAlgorithm = in.read();

        if (version == VERSION_3)
        {
            long keyID = 0;
            keyID |= (long) in.read() << 56;
            keyID |= (long) in.read() << 48;
            keyID |= (long) in.read() << 40;
            keyID |= (long) in.read() << 32;
            keyID |= (long) in.read() << 24;
            keyID |= (long) in.read() << 16;
            keyID |= (long) in.read() << 8;
            keyID |= in.read();
            this.keyID = keyID;

            isContaining = in.read();

            this.salt = null;
            this.keyFingerprint = null;
        }
        else if (version == VERSION_6)
        {
            keyID = 0;
            int expectedSaltSize = SignaturePacket.getSaltSize(hashAlgorithm);
            int saltSize = in.read();
            if (saltSize != expectedSaltSize)
            {
                Streams.drain(in);
                throw new UnsupportedPacketVersionException("Unexpected salt size " + expectedSaltSize + ", got " + saltSize);
            }

            salt = new byte[saltSize];
            in.readFully(salt);

            keyFingerprint = new byte[32];
            in.readFully(keyFingerprint);

            isContaining = in.read();
        }
        else
        {
            Streams.drain(in);
            throw new UnsupportedPacketVersionException("Unsupported One-Pass-Signature packet version encountered: " + version);
        }
    }

    public static OnePassSignaturePacket createVersion3Packet(
            int sigType,
            int hashAlgorithm,
            int keyAlgorithm,
            long keyID,
            boolean isNested)
    {
        return new OnePassSignaturePacket(sigType, hashAlgorithm, keyAlgorithm, keyID, isNested);
    }

    public static OnePassSignaturePacket createVersion6Packet(
            int sigType,
            int hashAlgorithm,
            int keyAlgorithm,
            byte[] salt,
            byte[] keyFingerprint,
            boolean isNested)
    {
        return new OnePassSignaturePacket(sigType, hashAlgorithm, keyAlgorithm, salt, keyFingerprint, isNested);
    }

    /**
     * Create an OPS packet of version {@link #VERSION_3}.
     * @param sigType signature type
     * @param hashAlgorithm hash algorithm identifier
     * @param keyAlgorithm public key algorithm identifier
     * @param keyID key id
     * @param isNested is nested flag
     */
    public OnePassSignaturePacket(
        int        sigType,
        int        hashAlgorithm,
        int        keyAlgorithm,
        long       keyID,
        boolean    isNested)
    {
        this(VERSION_3, sigType, hashAlgorithm, keyAlgorithm, null, keyID, null, isNested);
    }

    /**
     * Create an OPS packet of version {@link #VERSION_6}.
     *
     * @param sigType signature type
     * @param hashAlgorithm hash algorithm identifier
     * @param keyAlgorithm public key algorithm identifier
     * @param salt salt
     * @param keyFingerprint key fingerprint
     * @param isNested is nested flag
     */
    public OnePassSignaturePacket(
            int sigType,
            int hashAlgorithm,
            int keyAlgorithm,
            byte[] salt,
            byte[] keyFingerprint,
            boolean isNested)
    {
        this(VERSION_6, sigType, hashAlgorithm, keyAlgorithm, salt, 0, keyFingerprint, isNested);
    }

    public OnePassSignaturePacket(
            int version,
            int signatureType,
            int hashAlgorithm,
            int keyAlgorithm,
            byte[] salt,
            long keyID,
            byte[] keyFingerprint,
            boolean isNested)
    {
        this.version = version;
        this.sigType = signatureType;
        this.hashAlgorithm = hashAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keyID = keyID;
        this.keyFingerprint = keyFingerprint;
        this.salt = salt;
        this.isContaining = isNested ? 0 : 1;
    }

    public int getVersion()
    {
        return version;
    }

    /**
     * Return the signature type.
     * @return the signature type
     */
    public int getSignatureType()
    {
        return sigType;
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
     * Return the salt of the signature.
     * Only for {@link #VERSION_6}, returns <pre>null</pre> otherwise.
     *
     * @return salt
     */
    public byte[] getSalt() {
        if (salt != null) {
            return Arrays.clone(salt);
        }
        return null;
    }
    
    /**
     * Return the key-id of the issuing key.
     * Only for {@link #VERSION_3}. Signatures of version {@link #VERSION_6} use {@link #getKeyFingerprint()} instead.
     *
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return the v6 fingerprint of the issuing key.
     * Only for {@link #VERSION_6}. Signatures of version {@link #VERSION_3} use {@link #getKeyID()} instead.
     *
     * @return 32 byte array
     */
    public byte[] getKeyFingerprint() {
        if (keyFingerprint != null) {
            return Arrays.clone(keyFingerprint);
        }
        return null;
    }

    /**
     * Return true, if the signature contains any signatures that follow.
     * An bracketing OPS is followed by additional OPS packets and is calculated over all the data between itself
     * and its corresponding signature (it is an attestation for encapsulated signatures).
     *
     * @return true if encapsulating, false otherwise
     */
    public boolean isContaining()
    {
        return isContaining == 1;
    }
    
    /**
     * 
     */
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream            pOut = new BCPGOutputStream(bOut);
  
        pOut.write(version);
        pOut.write(sigType);
        pOut.write(hashAlgorithm);
        pOut.write(keyAlgorithm);

        if (version == VERSION_3)
        {
            pOut.write((byte) (keyID >> 56));
            pOut.write((byte) (keyID >> 48));
            pOut.write((byte) (keyID >> 40));
            pOut.write((byte) (keyID >> 32));
            pOut.write((byte) (keyID >> 24));
            pOut.write((byte) (keyID >> 16));
            pOut.write((byte) (keyID >> 8));
            pOut.write((byte) (keyID));
        }
        else if (version == VERSION_6)
        {
            pOut.write(salt.length);
            pOut.write(salt);

            pOut.write(keyFingerprint);
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported One-Pass-Signature version encountered: " + version);
        }
        
        pOut.write(isContaining);

        pOut.close();

        out.writePacket(ONE_PASS_SIGNATURE, bOut.toByteArray());
    }
}
