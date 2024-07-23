package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

/**
 * basic packet for a PGP public key
 */
public class PublicKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    public static final int VERSION_3 = 3;
    public static final int VERSION_4 = 4;
    public static final int LIBREPGP_5 = 5;
    public static final int VERSION_6 = 6;

    private int version;
    private long time;
    private int validDays;
    private int algorithm;
    private BCPGKey key;

    PublicKeyPacket(
            BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }
    PublicKeyPacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        this(PUBLIC_KEY, in, newPacketFormat);
    }

    PublicKeyPacket(
            int keyTag,
            BCPGInputStream in)
            throws IOException
    {
        this(keyTag, in, false);
    }

    /**
     * Parse a {@link PublicKeyPacket} or {@link PublicSubkeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * If <pre>packetTypeID</pre> is {@link #PUBLIC_KEY}, the packet is a primary key.
     * If instead it is {@link #PUBLIC_SUBKEY}, it is a subkey packet.
     * If <pre>newPacketFormat</pre> is true, the packet format is remembered as {@link PacketFormat#CURRENT},
     * otherwise as {@link PacketFormat#LEGACY}.
     * @param keyTag packet type ID
     * @param in packet input stream
     * @param newPacketFormat packet format
     * @throws IOException if the key packet cannot be parsed
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-3-public-keys">
     *     C-R - Version 3 Public Keys</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-4-public-keys">
     *     C-R - Version 4 Public Keys</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-6-public-keys">
     *     C-R - Version 6 Public Keys</a>
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

        time = ((long) in.read() << 24) | ((long) in.read() << 16) | ((long) in.read() << 8) | in.read();

        if (version == 2 || version == VERSION_3)
        {
            validDays = (in.read() << 8) | in.read();
        }

        algorithm = (byte)in.read();
        long keyOctets = -1;
        
        if (version == LIBREPGP_5 || version == VERSION_6)
        {
            // TODO: Use keyOctets to be able to parse unknown keys
            keyOctets = ((long)in.read() << 24) | ((long)in.read() << 16) | ((long)in.read() << 8) | in.read();
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
     * Construct version 4 public key packet.
     *
     * @param algorithm
     * @param time
     * @param key
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

    public PublicKeyPacket(
         int version,
         int algorithm,
         Date time,
         BCPGKey key)
     {
         this(PUBLIC_KEY, version, algorithm, time, key);
     }

    PublicKeyPacket(int keyTag, int version, int algorithm, Date time, BCPGKey key)
    {
        super(keyTag);

        this.version = version;
        this.time = time.getTime() / 1000;
        this.algorithm = algorithm;
        this.key = key;
    }


    public int getVersion()
    {
        return version;
    }

    public int getAlgorithm()
    {
        return algorithm;
    }

    public int getValidDays()
    {
        return validDays;
    }

    public Date getTime()
    {
        return new Date(time * 1000);
    }

    public BCPGKey getKey()
    {
        return key;
    }

    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(version);

        StreamUtil.writeTime(pOut, time);

        if (version <= VERSION_3)
        {
            pOut.write((byte)(validDays >> 8));
            pOut.write((byte)validDays);
        }

        pOut.write(algorithm);

        if (version == VERSION_6 || version == LIBREPGP_5)
        {
            int keyOctets = key.getEncoded().length;
            StreamUtil.write4OctetLength(pOut, keyOctets);
        }

        pOut.writeObject((BCPGObject)key);

        pOut.close();

        return bOut.toByteArray();
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), getPacketTag(), getEncodedContents());
    }
}
