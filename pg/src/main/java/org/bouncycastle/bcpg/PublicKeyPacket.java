package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.util.Pack;

/**
 * Base class for OpenPGP public (primary) keys.
 * The public key packet holds the public parameters of an OpenPGP key pair.
 * An OpenPGP certificate (transferable public key) consists of one primary key and optionally multiple subkey packets.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-5.5.1.1">
 *     RFC4880 - Public-Key Packet</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-packet-type-id-6">
 *     RFC9580 - Public-Key Packet</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-public-key-packet-tag-6">
 *     LibrePGP - Public-Key Packet</a>
 */
public class PublicKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    /**
     * OpenPGP v3 keys are deprecated.
     * They can only be used with RSA.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-public-keys">
     *     OpenPGP - Version 3 Public Keys</a>
     */
    public static final int VERSION_3 = 3;
    /**
     * OpenPGP v4 keys are (at the time of writing) widely used, but are subject to some attacks.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-4-public-keys">
     *     OpenPGP - Version 4 Public Keys</a>
     */
    public static final int VERSION_4 = 4;
    /**
     * Non-Standard LibrePGP introduced v5, which is only supported by a subset of vendors.
     */
    public static final int LIBREPGP_5 = 5;
    /**
     * OpenPGP v6 keys are newly introduced.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-keys">
     *     OpenPGP - Version 6 Public Keys</a>
     */
    public static final int VERSION_6 = 6;

    private int version;
    // Creation time of the key stored as seconds since epoch
    private long time;
    private int validDays;
    private int algorithm;
    private BCPGKey key;

    /**
     * Parse a {@link PublicKeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * The packet format is remembered as {@link PacketFormat#LEGACY}.
     * @param in packet input stream
     * @throws IOException
     */
    PublicKeyPacket(
            BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }

    /**
     * Parse a {@link PublicKeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * If <pre>newPacketFormat</pre> is true, the packet format is remembered as {@link PacketFormat#CURRENT},
     * otherwise as {@link PacketFormat#LEGACY}.
     * @param in packet input stream
     * @param newPacketFormat new packet format
     * @throws IOException
     */
    PublicKeyPacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        this(PUBLIC_KEY, in, newPacketFormat);
    }

    /**
     * Parse a {@link PublicKeyPacket} or {@link PublicSubkeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * If <pre>keyTag</pre> is {@link #PUBLIC_KEY}, the packet is a primary key.
     * If instead it is {@link #PUBLIC_SUBKEY}, it is a subkey packet.
     * The packet format is remembered as {@link PacketFormat#LEGACY}.
     * @param keyTag packet type ID
     * @param in packet input stream
     * @throws IOException
     */
    PublicKeyPacket(
            int keyTag,
            BCPGInputStream in)
            throws IOException
    {
        this(keyTag, in, false);
    }

    /**
     * Parse a {@link PublicKeyPacket} or {@link PublicSubkeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * If <pre>keyTag</pre> is {@link #PUBLIC_KEY}, the packet is a primary key.
     * If instead it is {@link #PUBLIC_SUBKEY}, it is a subkey packet.
     * If <pre>newPacketFormat</pre> is true, the packet format is remembered as {@link PacketFormat#CURRENT},
     * otherwise as {@link PacketFormat#LEGACY}.
     * @param keyTag packet type ID
     * @param in packet input stream
     * @param newPacketFormat packet format
     * @throws IOException if the key packet cannot be parsed
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-public-keys">
     *     OpenPGP - Version 3 Public Keys</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-4-public-keys">
     *     OpenPGP - Version 4 Public Keys</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-keys">
     *     OpenPGP - Version 6 Public Keys</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-public-key-packet-formats">
     *     LibrePGP - Public-Key Packet Formats</a>
     */
    PublicKeyPacket(
        int keyTag,
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        super(keyTag, newPacketFormat);

        version = in.read();
        if (version < 2 || version > VERSION_6)
        {
            throw new UnsupportedPacketVersionException("Unsupported Public Key Packet version encountered: " + version);
        }

        time = StreamUtil.read4OctetLength(in) & 0xFFFFFFFFL;

        if (version == 2 || version == VERSION_3)
        {
            validDays = StreamUtil.read2OctetLength(in);
        }

        algorithm = (byte)in.read();
        long keyOctets = -1;

        if (version == LIBREPGP_5 || version == VERSION_6)
        {
            // TODO: Use keyOctets to be able to parse unknown keys
            keyOctets = StreamUtil.read4OctetLength(in);
        }

        parseKey(in, algorithm, keyOctets);
    }

    /**
     * Parse algorithm-specific public key material.
     * @param in input stream which read just up to the public key material
     * @param algorithmId public key algorithm ID
     * @param optLen optional: Length of the public key material. -1 if not present.
     * @throws IOException if the pk material cannot be parsed
     */
    private void parseKey(BCPGInputStream in, int algorithmId, long optLen)
        throws IOException
    {

        switch (algorithmId)
        {
        case RSA_ENCRYPT:
        case RSA_GENERAL:
        case RSA_SIGN:
            key = new RSAPublicBCPGKey(in);
            break;
        case DSA:
            key = new DSAPublicBCPGKey(in);
            break;
        case ELGAMAL_ENCRYPT:
        case ELGAMAL_GENERAL:
            key = new ElGamalPublicBCPGKey(in);
            break;
        case ECDH:
            key = new ECDHPublicBCPGKey(in);
            break;
        case X25519:
            key = new X25519PublicBCPGKey(in);
            break;
        case X448:
            key = new X448PublicBCPGKey(in);
            break;
        case ECDSA:
            key = new ECDSAPublicBCPGKey(in);
            break;
        case EDDSA_LEGACY:
            key = new EdDSAPublicBCPGKey(in);
            break;
        case Ed25519:
            key = new Ed25519PublicBCPGKey(in);
            break;
        case Ed448:
            key = new Ed448PublicBCPGKey(in);
            break;
        default:
            if (version == VERSION_6 || version == LIBREPGP_5)
            {
                // with version 5 & 6, we can gracefully handle unknown key types, as the length is known.
                key = new UnknownBCPGKey((int) optLen, in);
                break;
            }
            throw new IOException("unknown PGP public key algorithm encountered: " + algorithm);
        }
    }

    /**
     * Construct version 4 public primary key packet.
     *
     * @param algorithm public key algorithm id
     * @param time creation time
     * @param key key object
     * @deprecated use versioned {@link #PublicKeyPacket(int, int, Date, BCPGKey)} instead
     */
    @Deprecated
    public PublicKeyPacket(
        int algorithm,
        Date time,
        BCPGKey key)
    {
        this(VERSION_4, algorithm, time, key);
    }

    /**
     * Construct an OpenPGP public primary key packet.
     * @param version packet version
     * @param algorithm public key algorithm id
     * @param time creation time
     * @param key key object
     */
    public PublicKeyPacket(
         int version,
         int algorithm,
         Date time,
         BCPGKey key)
    {
        this(PUBLIC_KEY, version, algorithm, time, key);
    }

    /**
     * Construct an OpenPGP public key packet.
     * If <pre>keyTag</pre> is {@link #PUBLIC_KEY}, the packet is a primary key.
     * If instead it is {@link #PUBLIC_SUBKEY}, it is a subkey packet.
     * @param keyTag public key packet type ID
     * @param version packet version
     * @param algorithm public key algorithm id
     * @param time creation time
     * @param key key object
     */
    PublicKeyPacket(int keyTag, int version, int algorithm, Date time, BCPGKey key)
    {
        super(keyTag);

        this.version = version;
        this.time = time.getTime() / 1000;
        this.algorithm = algorithm;
        this.key = key;
    }

    /**
     * Return the packet version.
     * @return packet version
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Return the {@link PublicKeyAlgorithmTags algorithm id} of the public key.
     * @return algorithm id
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Only for v3 keys - The time in days since the keys creation, during which the key is valid.
     *
     * @return v3 key validity period in days since creation.
     * @deprecated v4 and v6 keys instead signal their expiration time via the
     * {@link org.bouncycastle.bcpg.sig.KeyExpirationTime} signature subpacket.
     */
    public int getValidDays()
    {
        return validDays;
    }

    /**
     * Return the keys creation time.
     * @return creation time of the key
     */
    public Date getTime()
    {
        return new Date(time * 1000);
    }

    /**
     * Return the key object.
     * @return key
     */
    public BCPGKey getKey()
    {
        return key;
    }

    /**
     * Return the encoded packet contents without the packet frame.
     * @return encoded packet contents
     * @throws IOException
     */
    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(version);

        StreamUtil.writeSeconds(pOut, time);

        if (version <= VERSION_3)
        {
            StreamUtil.write2OctetLength(pOut, validDays);
        }

        pOut.write(algorithm);

        if (version == VERSION_6 || version == LIBREPGP_5)
        {
            StreamUtil.write4OctetLength(pOut, key.getEncoded().length);
        }

        pOut.writeObject((BCPGObject)key);

        pOut.close();

        return bOut.toByteArray();
    }

    /**
     * Encode the packet to the OpenPGP {@link BCPGOutputStream}.
     * If the {@link BCPGOutputStream} packet format is set to {@link PacketFormat#ROUNDTRIP}, the result
     * of {@link #hasNewPacketFormat()} determines, which packet format is used to encode the packet.
     * Otherwise, the {@link BCPGOutputStream} dictates which format to use.
     * @param out packet output stream
     * @throws IOException
     */
    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), getPacketTag(), getEncodedContents());
    }

    public static long getKeyID(PublicKeyPacket publicPk, byte[] fingerprint)
    {
        if (publicPk.version <= PublicKeyPacket.VERSION_3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)publicPk.key;

            return rK.getModulus().longValue();
        }
        else if (publicPk.version == PublicKeyPacket.VERSION_4)
        {
            return Pack.bigEndianToLong(fingerprint, fingerprint.length - 8);
        }
        else if (publicPk.version == PublicKeyPacket.LIBREPGP_5 || publicPk.version == PublicKeyPacket.VERSION_6)
        {
            return Pack.bigEndianToLong(fingerprint, 0);
        }

        return 0;
    }
}
