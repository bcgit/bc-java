package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * One-Pass-Signature packet.
 * OPS packets are used to enable verification of signed messages in one-pass by providing necessary metadata
 * about the signed data up front, so the consumer can start processing the signed data without needing
 * to process the signature packet at the end of the data stream first.
 * <b>
 * There are two versions of this packet currently defined.
 * Version 3 OPS packets are used with {@link SignaturePacket SignaturePackets} of version 3 and 4.
 * Version 6 OPS packets are used with {@link SignaturePacket SignaturePackets} of version 6.
 * It is not clear to me, which version of the OPS packet is intended to be used with version 5 signatures.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-5.4">
 *     Definition of version 3 OPS packets in RFC4880</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-one-pass-signature-packet-t">
 *     Definition of version 3 and 6 OPS packets in crypto-refresh</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#section-5.4">
 *     Definition of version 3 and 6 OPS packets in librepgp</a>
 */
public class OnePassSignaturePacket 
    extends ContainedPacket
{
    public static final int VERSION_3 = 3;
    public static final int VERSION_6 = 6;

    private final int  version;
    private final int  sigType;
    private final int  hashAlgorithm;
    private final int  keyAlgorithm;
    private final long keyID;
    private final byte[] fingerprint;
    private final byte[] salt;
    private final int isContaining;

    /**
     * Parse a {@link OnePassSignaturePacket} from an OpenPGP packet input stream.
     * @param in OpenPGP packet input stream
     * @throws IOException when the end of stream is prematurely reached, or when the packet is malformed
     */
    OnePassSignaturePacket(
            BCPGInputStream    in)
            throws IOException
    {
        this(in, false);
    }

    OnePassSignaturePacket(
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {
        super(ONE_PASS_SIGNATURE, newPacketFormat);

        version = in.read();
        sigType = in.read();
        hashAlgorithm = in.read();
        keyAlgorithm = in.read();

        if (version == VERSION_3)
        {
            keyID = StreamUtil.readKeyID(in);
            fingerprint = null;
            salt = null;
        }
        else if (version == VERSION_6)
        {
            int saltLen = in.read();
            if (saltLen < 0)
            {
                throw new IOException("Version 6 OPS packet has invalid salt length.");
            }
            salt = new byte[saltLen];
            in.readFully(salt);

            fingerprint = new byte[32];
            in.readFully(fingerprint);

            keyID = FingerprintUtil.keyIdFromV6Fingerprint(fingerprint);
        }
        else
        {
            Streams.drain(in);
            throw new UnsupportedPacketVersionException("Unsupported OnePassSignature packet version encountered: " + version);
        }

        isContaining = in.read();
    }

    /**
     * Create a version 3 {@link OnePassSignaturePacket}.
     * Version 3 OPS packets are used with version 3 and version 4 {@link SignaturePacket SignaturePackets}.
     * <b>
     * To create an OPS packet for use with a version 6 {@link SignaturePacket},
     * see {@link OnePassSignaturePacket#OnePassSignaturePacket(int, int, int, byte[], byte[], boolean)}.
     *
     * @param sigType signature type
     * @param hashAlgorithm hash algorithm tag
     * @param keyAlgorithm public key algorithm tag
     * @param keyID id of the signing key
     * @param isNested if false, there is another OPS packet after this one, which applies to the same data.
     *                 it true, the corresponding signature is calculated also over succeeding additional OPS packets.
     */
    public OnePassSignaturePacket(
        int        sigType,
        int        hashAlgorithm,
        int        keyAlgorithm,
        long       keyID,
        boolean    isNested)
    {
        super(ONE_PASS_SIGNATURE);

        this.version = VERSION_3;
        this.sigType = sigType;
        this.hashAlgorithm = hashAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keyID = keyID;
        this.fingerprint = null;
        this.salt = null;
        this.isContaining = (isNested) ? 0 : 1;
    }

    /**
     * Create a version 6 {@link OnePassSignaturePacket}.
     *
     * @param sigType signature type
     * @param hashAlgorithm hash algorithm tag
     * @param keyAlgorithm public key algorithm tag
     * @param salt random salt. The length of this array depends on the hash algorithm in use.
     * @param fingerprint 32 octet fingerprint of the (v6) signing key
     * @param isNested if false, there is another OPS packet after this one, which applies to the same data.
     *                 it true, the corresponding signature is calculated also over succeeding additional OPS packets.
     */
    public OnePassSignaturePacket(
            int sigType,
            int hashAlgorithm,
            int keyAlgorithm,
            byte[] salt,
            byte[] fingerprint,
            boolean isNested)
    {
        super(ONE_PASS_SIGNATURE);

        this.version = VERSION_6;
        this.sigType = sigType;
        this.hashAlgorithm = hashAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.salt = salt;
        this.fingerprint = fingerprint;
        this.isContaining = (isNested) ? 0 : 1;
        keyID = FingerprintUtil.keyIdFromV6Fingerprint(fingerprint);
    }

    /**
     * Return the packet version.
     * @return version
     */
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
     * Return the ID of the public key encryption algorithm.
     * @return public key algorithm tag
     */
    public int getKeyAlgorithm()
    {
        return keyAlgorithm;
    }
    
    /**
     * Return the algorithm ID of the hash algorithm.
     * @return hash algorithm tag
     */
    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    /**
     * Return the key-id of the signing key.
     * @return key id
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return the version 6 fingerprint of the issuer.
     * Only for version 6 packets.
     * @return 32 bytes issuer fingerprint
     */
    public byte[] getFingerprint()
    {
        return Arrays.clone(fingerprint);
    }

    /**
     * Return the salt used in the signature.
     * Only for version 6 packets.
     * @return salt
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * Return true, if the signature contains any signatures that follow.
     * A bracketing OPS is followed by additional OPS packets and is calculated over all the data between itself
     * and its corresponding signature (it is an attestation for encapsulated signatures).
     *
     * @return true if encapsulating, false otherwise
     */
    public boolean isContaining()
    {
        return isContaining == 1;
    }
    
    /**
     * Encode the contents of this packet into the given packet output stream.
     *
     * @param out OpenPGP packet output stream
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
            StreamUtil.writeKeyID(pOut, keyID);
        }
        else if (version == VERSION_6)
        {
            pOut.write(salt.length);
            pOut.write(salt);
            pOut.write(fingerprint);
        }

        pOut.write(isContaining);

        pOut.close();

        out.writePacket(hasNewPacketFormat(), ONE_PASS_SIGNATURE, bOut.toByteArray());
    }

}
