package org.bouncycastle.bcpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * Base class for OpenPGP secret (primary) keys.
 */
public class SecretKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    /**
     * S2K-usage octet indicating that the secret key material is unprotected.
     */
    public static final int USAGE_NONE = 0x00;

    /**
     * S2K-usage octet indicating that the secret key material is protected using malleable CFB.
     * Malleable-CFB-encrypted keys are vulnerable to corruption attacks
     * that can cause leakage of secret data when the secret key is used.
     *
     * @see <a href="https://eprint.iacr.org/2002/076">
     * Klíma, V. and T. Rosa,
     * "Attack on Private Signature Keys of the OpenPGP Format,
     * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     * Bruseghini, L., Paterson, K. G., and D. Huigens,
     * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
     * @deprecated Use of MalleableCFB is deprecated.
     * For v4 keys, use {@link #USAGE_SHA1} instead.
     * For v6 keys use {@link #USAGE_AEAD} instead.
     */
    public static final int USAGE_CHECKSUM = 0xff;

    /**
     * S2K-usage octet indicating that the secret key material is protected using a cipher in CFB mode.
     * CFB-encrypted keys are vulnerable to corruption attacks that can
     * cause leakage of secret data when the secret key is use.
     *
     * @see <a href="https://eprint.iacr.org/2002/076">
     * Klíma, V. and T. Rosa,
     * "Attack on Private Signature Keys of the OpenPGP Format,
     * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     * Bruseghini, L., Paterson, K. G., and D. Huigens,
     * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
     */
    public static final int USAGE_SHA1 = 0xfe;

    /**
     * S2K-usage octet indicating that the secret key material is protected using an AEAD scheme.
     * This usage protects against above-mentioned attacks.
     * Passphrase-protected secret key material in a v6 Secret Key or
     * v6 Secret Subkey packet SHOULD be protected with AEAD encryption
     * unless it will be transferred to an implementation that is known
     * to not support AEAD.
     * Users should migrate to AEAD with all due speed.
     */
    public static final int USAGE_AEAD = 0xfd;
    
    private PublicKeyPacket pubKeyPacket;
    private byte[] secKeyData;
    private int s2kUsage;
    private int encAlgorithm;
    private int aeadAlgorithm;
    private S2K s2k;
    private byte[] iv;

    /**
     * Parse a primary OpenPGP secret key packet from the given OpenPGP {@link BCPGInputStream}.
     * The packet format is remembered as {@link PacketFormat#LEGACY}.
     * @param in packet input stream
     * @throws IOException
     */
    SecretKeyPacket(
            BCPGInputStream in)
            throws IOException
    {
        this(SECRET_KEY, in);
    }

    /**
     * Parse a primary OpenPGP secret key packet from the given OpenPGP {@link BCPGInputStream}.
     * If <pre>newPacketFormat</pre> is true, the packet format will be remembered as {@link PacketFormat#CURRENT},
     * otherwise as {@link PacketFormat#LEGACY}.
     * @param in packet input stream
     * @param newPacketFormat current or legacy packet format
     * @throws IOException
     */
    SecretKeyPacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        this(SECRET_KEY, in, newPacketFormat);
    }

    /**
     * Parse a {@link SecretKeyPacket} or {@link SecretSubkeyPacket} from the given OpenPGP {@link BCPGInputStream}.
     * The return type depends on the <pre>keyTag</pre>:
     * {@link PacketTags#SECRET_KEY} means the result is a {@link SecretKeyPacket}.
     * {@link PacketTags#SECRET_SUBKEY} results in a {@link SecretSubkeyPacket}.
     * The packet format will be remembered as {@link PacketFormat#LEGACY}.
     * @param keyTag packet type ID
     * @param in packet input stream
     * @throws IOException
     */
    SecretKeyPacket(
            int keyTag,
            BCPGInputStream in)
            throws IOException
    {
        this(keyTag, in, false);
    }

    /**
     * Parse a {@link SecretKeyPacket} or {@link SecretSubkeyPacket} from an OpenPGP {@link BCPGInputStream}.
     * The return type depends on the <pre>keyTag</pre>:
     * {@link PacketTags#SECRET_KEY} means the result is a {@link SecretKeyPacket}.
     * {@link PacketTags#SECRET_SUBKEY} results in a {@link SecretSubkeyPacket}.
     *
     * @param keyTag packet type ID
     * @param in packet input stream
     * @param newPacketFormat packet format
     * @throws IOException if the secret key packet cannot be parsed
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats">
     *     OpenPGP - Secret-Key Packet Formats</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-secret-key-packet-formats">
     *     LibrePGP - Secret-Key Packet Formats</a>
     * @see <a href="https://datatracker.ietf.org/doc/draft-dkg-openpgp-hardware-secrets/">
     *     Hardware-Backed Secret Keys</a>
     */
    SecretKeyPacket(
        int keyTag,
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        super(keyTag, newPacketFormat);

        if (this instanceof SecretSubkeyPacket)
        {
            pubKeyPacket = new PublicSubkeyPacket(in, newPacketFormat);
        }
        else
        {
            pubKeyPacket = new PublicKeyPacket(in, newPacketFormat);
        }

        int version = pubKeyPacket.getVersion();
        s2kUsage = in.read();

        int conditionalParameterLength = -1;
        if (version == PublicKeyPacket.LIBREPGP_5 || 
           (version == PublicKeyPacket.VERSION_6 && s2kUsage != USAGE_NONE))
        {
            // TODO: Use length to parse unknown parameters
            conditionalParameterLength = in.read();
        }

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD)
        {
            encAlgorithm = in.read();
        }
        else
        {
            encAlgorithm = s2kUsage;
        }
        if (s2kUsage == USAGE_AEAD)
        {
            aeadAlgorithm = in.read();
        }
        if (version == PublicKeyPacket.VERSION_6 && (s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD))
        {
            int s2KLen = in.read();
            byte[] s2kBytes = new byte[s2KLen];
            in.readFully(s2kBytes);

            // TODO: catch UnsupportedPacketVersionException gracefully
            s2k = new S2K(new ByteArrayInputStream(s2kBytes));
        }
        else
        {
            if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD)
            {
                s2k = new S2K(in);
            }
        }
        if (s2kUsage == USAGE_AEAD)
        {
            iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
            Streams.readFully(in, iv);
        }
        else
        {
            boolean isGNUDummyNoPrivateKey = s2k != null
                && s2k.getType() == S2K.GNU_DUMMY_S2K
                && s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY;
            if (!(isGNUDummyNoPrivateKey))
            {
                if (s2kUsage != USAGE_NONE && iv == null)
                {
                    if (encAlgorithm < 7)
                    {
                        iv = new byte[8];
                    } 
                    else
                    {
                        iv = new byte[16];
                    }
                    in.readFully(iv, 0, iv.length);
                }
            }
        }
        
        if (version == PublicKeyPacket.LIBREPGP_5)
        {
            long keyOctetCount = ((long) in.read() << 24) | ((long) in.read() << 16) | ((long) in.read() << 8) | in.read();
            if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_NONE)
            {
                // encoded keyOctetCount does not contain checksum
                keyOctetCount += 2;
            }
            this.secKeyData = new byte[(int) keyOctetCount];
            in.readFully(secKeyData);
        }
        else
        {
            this.secKeyData = in.readAll();
        }
    }

    /**
     * Construct a {@link SecretKeyPacket}.
     * Note: <pre>secKeyData</pre> needs to be prepared by applying encryption/checksum beforehand.
     * @param pubKeyPacket pubkey packet corresponding to this secret key packet.
     * @param encAlgorithm algorithm id of the symmetric key algorithm that was used to encrypt the secret key material
     * @param s2k s2k identifier for deriving a key from a passphrase
     * @param iv IV that was used to encrypt the secret key material
     * @param secKeyData encrypted/checksum'd secret key material
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(SECRET_KEY, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData);
    }

    /**
     * Construct a {@link SecretKeyPacket} or {@link SecretSubkeyPacket}.
     * Note: <pre>secKeyData</pre> needs to be prepared by applying encryption/checksum beforehand.
     * @param keyTag packet type ID
     * @param pubKeyPacket pubkey packet corresponding to this secret key packet.
     * @param encAlgorithm algorithm id of the symmetric key algorithm that was used to encrypt the secret key material
     * @param s2k s2k identifier for deriving a key from a passphrase
     * @param iv IV that was used to encrypt the secret key material
     * @param secKeyData encrypted/checksum'd secret key material
     */
    SecretKeyPacket(
        int keyTag,
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(keyTag, pubKeyPacket, encAlgorithm, 0, encAlgorithm != SymmetricKeyAlgorithmTags.NULL ? USAGE_CHECKSUM : USAGE_NONE, s2k, iv, secKeyData);
    }

    /**
     * Construct a {@link SecretKeyPacket} or {@link SecretSubkeyPacket}.
     * Note: <pre>secKeyData</pre> needs to be prepared by applying encryption/checksum beforehand.
     * @param pubKeyPacket pubkey packet corresponding to this secret key packet.
     * @param encAlgorithm algorithm id of the symmetric key algorithm that was used to encrypt the secret key material
     * @param s2kUsage octet indicating, how the secert key material was protected
     * @param s2k s2k identifier for deriving a key from a passphrase
     * @param iv IV that was used to encrypt the secret key material
     * @param secKeyData encrypted/checksum'd secret key material
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(SECRET_KEY, pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Construct a {@link SecretKeyPacket} or {@link SecretSubkeyPacket}.
     * Note: <pre>secKeyData</pre> needs to be prepared by applying encryption/checksum beforehand.
     * @param pubKeyPacket pubkey packet corresponding to this secret key packet.
     * @param encAlgorithm algorithm id of the symmetric key algorithm that was used to encrypt the secret key material
     * @param aeadAlgorithm AEAD algorithm scheme used to protect the secret key material with
     * @param s2kUsage octet indicating how the secret key material was encrypted
     * @param s2k s2k identifier for deriving a key from a passphrase
     * @param iv IV that was used to encrypt the secret key material
     * @param secKeyData encrypted/checksum'd secret key material
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int aeadAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(SECRET_KEY, pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Construct a {@link SecretKeyPacket} or {@link SecretSubkeyPacket}.
     * Note: <pre>secKeyData</pre> needs to be prepared by applying encryption/checksum beforehand.
     * @param keyTag packet type ID
     * @param pubKeyPacket pubkey packet corresponding to this secret key packet.
     * @param encAlgorithm algorithm id of the symmetric key algorithm that was used to encrypt the secret key material
     * @param aeadAlgorithm AEAD algorithm scheme used to protect the secret key material with
     * @param s2kUsage octet indicating how the secret key material was encrypted
     * @param s2k s2k identifier for deriving a key from a passphrase
     * @param iv IV that was used to encrypt the secret key material
     * @param secKeyData encrypted/checksum'd secret key material
     */
    SecretKeyPacket(
        int keyTag,
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int aeadAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        super(keyTag, pubKeyPacket.hasNewPacketFormat());

        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.s2kUsage = s2kUsage;
        this.s2k = s2k;
        this.iv = Arrays.clone(iv);
        this.secKeyData = secKeyData;

        if (s2k != null && s2k.getType() == S2K.ARGON_2 && s2kUsage != USAGE_AEAD)
        {
            throw new IllegalArgumentException("Argon2 is only used with AEAD (S2K usage octet 253)");
        }

        if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6)
        {
            if (s2kUsage == USAGE_CHECKSUM)
            {
                throw new IllegalArgumentException("Version 6 keys MUST NOT use S2K usage USAGE_CHECKSUM");
            }
        }
    }

    /**
     * Return the algorithm ID of the symmetric key algorithm that was used to encrypt the secret key material.
     * @return symmetric key enc algorithm id
     */
    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }

    /**
     * Return the algorithm ID of the AEAD algorithm that was used to protect the secret key material.
     * @return aead algorithm id
     */
    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
    }

    /**
     * Return the S2K usage mode indicating how the secret key material is protected.
     * @return s2k usage
     */
    public int getS2KUsage()
    {
        return s2kUsage;
    }

    /**
     * Return the IV that was used to protect the secret key material.
     * @return IV
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }

    /**
     * Return the S2K identifier describing, how to derive the symmetric key to protect the secret key material with.
     * @return s2k identifier
     */
    public S2K getS2K()
    {
        return s2k;
    }

    /**
     * Return the public key packet corresponding to the secret key packet.
     * @return public key packet
     */
    public PublicKeyPacket getPublicKeyPacket()
    {
        return pubKeyPacket;
    }

    /**
     * Return the encrypted/checksum'd secret key data.
     * @return secret key data
     */
    public byte[] getSecretKeyData()
    {
        return secKeyData;
    }

    /**
     * Return the encoded packet content without packet frame.
     * @return encoded packet contents
     * @throws IOException
     */
    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(pubKeyPacket.getEncodedContents());

        pOut.write(s2kUsage);

        // conditional parameters
        byte[] conditionalParameters = encodeConditionalParameters();
        if (pubKeyPacket.getVersion() == PublicKeyPacket.LIBREPGP_5 || 
           (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6 && s2kUsage != USAGE_NONE))
        {
            pOut.write(conditionalParameters.length);
        }
        pOut.write(conditionalParameters);

        // encrypted secret key
        if (secKeyData != null && secKeyData.length > 0)
        {
            if (pubKeyPacket.getVersion() == PublicKeyPacket.LIBREPGP_5)
            {
                int keyOctetCount = secKeyData.length;
                // v5 keyOctetCount does not include checksum octets
                if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_NONE)
                {
                    keyOctetCount -= 2;
                }
                StreamUtil.write4OctetLength(pOut, keyOctetCount);
            }
            pOut.write(secKeyData);
        }

        pOut.close();

        return bOut.toByteArray();
    }

    private byte[] encodeConditionalParameters()
        throws IOException
    {
        ByteArrayOutputStream conditionalParameters = new ByteArrayOutputStream();
        boolean hasS2KSpecifier = s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD;

        if (hasS2KSpecifier)
        {
            conditionalParameters.write(encAlgorithm);
            if (s2kUsage == USAGE_AEAD)
            {
                conditionalParameters.write(aeadAlgorithm);
            }
            byte[] encodedS2K = s2k.getEncoded();
            if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6)
            {
                conditionalParameters.write(encodedS2K.length);
            }
            conditionalParameters.write(encodedS2K);
        }
        if (iv != null)
        {
            // since USAGE_AEAD and other types that use an IV are mutually exclusive,
            // we use the IV field for both v4 IVs and v6 AEAD nonces
            conditionalParameters.write(iv);
        }

        return conditionalParameters.toByteArray();
    }

    /**
     * Encode the packet into the given {@link BCPGOutputStream}.
     * If the packet output stream has {@link PacketFormat#ROUNDTRIP} set, the packet format to encode the packet length
     * with depends on the result of {@link #hasNewPacketFormat()}.
     * Otherwise, the packet output stream dictates the packet format.
     * @param out packet output stream
     * @throws IOException
     */
    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), getPacketTag(), getEncodedContents());
    }
}
