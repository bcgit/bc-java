package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Properties;

import java.io.IOException;
import java.math.BigInteger;

public abstract class PublicKeyKeyEncryptionMethodGenerator
    implements PGPKeyEncryptionMethodGenerator
{
    public static final String SESSION_KEY_OBFUSCATION_PROPERTY = "org.bouncycastle.openpgp.session_key_obfuscation";
    public static final long WILDCARD_KEYID = 0L;
    public static final byte[] WILDCARD_FINGERPRINT = new byte[0];

    private static boolean getSessionKeyObfuscationDefault()
    {
        // by default we want this to be true.
        return !Properties.isOverrideSetTo(SESSION_KEY_OBFUSCATION_PROPERTY, false);
    }

    private final PGPPublicKey pubKey;

    protected boolean sessionKeyObfuscation;
    protected boolean useWildcardRecipient;

    protected PublicKeyKeyEncryptionMethodGenerator(
        PGPPublicKey pubKey)
    {
        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
        case PGPPublicKey.ECDH:
        case PGPPublicKey.X25519:
        case PGPPublicKey.X448:
            break;
        case PGPPublicKey.RSA_SIGN:
            throw new IllegalArgumentException("Can't use an RSA_SIGN key for encryption.");
        case PGPPublicKey.DSA:
            throw new IllegalArgumentException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new IllegalArgumentException("Can't use ECDSA for encryption.");
        case PublicKeyAlgorithmTags.Ed448:
        case PublicKeyAlgorithmTags.Ed25519:
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            throw new IllegalArgumentException("Can't use EdDSA for encryption.");
        default:
            throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        this.pubKey = pubKey;
        this.sessionKeyObfuscation = getSessionKeyObfuscationDefault();
    }

    /**
     * Controls whether to obfuscate the size of ECDH session keys using extra padding where necessary.
     * <p>
     * The default behaviour can be configured using the system property
     * "org.bouncycastle.openpgp.session_key_obfuscation", or else it will default to enabled.
     * </p>
     *
     * @return the current generator.
     */
    public PublicKeyKeyEncryptionMethodGenerator setSessionKeyObfuscation(boolean enabled)
    {
        this.sessionKeyObfuscation = enabled;

        return this;
    }

    /**
     * Controls whether the recipient key ID/fingerprint is hidden (replaced by a wildcard value).
     *
     * @param enabled boolean
     * @return this
     * @deprecated use {@link #setUseWildcardRecipient(boolean)} instead
     * TODO: Remove in a future release
     */
    @Deprecated
    public PublicKeyKeyEncryptionMethodGenerator setUseWildcardKeyID(boolean enabled)
    {
        return setUseWildcardRecipient(enabled);
    }

    /**
     * Controls whether the recipient key ID/fingerprint is hidden (replaced by a wildcard value).
     *
     * @param enabled boolean
     * @return this
     */
    public PublicKeyKeyEncryptionMethodGenerator setUseWildcardRecipient(boolean enabled)
    {
        this.useWildcardRecipient = enabled;
        return this;
    }

    public byte[][] encodeEncryptedSessionInfo(
        byte[] encryptedSessionInfo)
        throws PGPException
    {
        byte[][] data;

        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            data = new byte[1][];

            data[0] = convertToEncodedMPI(encryptedSessionInfo);
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            byte[] b1 = new byte[encryptedSessionInfo.length / 2];
            byte[] b2 = new byte[encryptedSessionInfo.length / 2];

            System.arraycopy(encryptedSessionInfo, 0, b1, 0, b1.length);
            System.arraycopy(encryptedSessionInfo, b1.length, b2, 0, b2.length);

            data = new byte[2][];
            data[0] = convertToEncodedMPI(b1);
            data[1] = convertToEncodedMPI(b2);
            break;
        case PGPPublicKey.ECDH:
        case PGPPublicKey.X448:
        case PGPPublicKey.X25519:
            data = new byte[1][];

            data[0] = encryptedSessionInfo;
            break;
        default:
            throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        return data;
    }

    private byte[] convertToEncodedMPI(byte[] encryptedSessionInfo)
        throws PGPException
    {
        try
        {
            return new MPInteger(new BigInteger(1, encryptedSessionInfo)).getEncoded();
        }
        catch (IOException e)
        {
            throw new PGPException("Invalid MPI encoding: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a Public-Key Encrypted Session-Key (PKESK) packet of version 3.
     * PKESKv3 packets are used with Symmetrically-Encrypted-Integrity-Protected Data (SEIPD) packets of
     * version 1 or with Symmetrically-Encrypted Data (SED) packets and MUST NOT be used with SEIPDv2 packets.
     * PKESKv3 packets are used with keys that do not support {@link org.bouncycastle.bcpg.sig.Features#FEATURE_SEIPD_V2}
     * or as a fallback.
     *
     * @param sessionInfo session-key algorithm + session-key + checksum
     * @return version 3 PKESK packet
     *
     * @throws PGPException
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-public-key-encryp">
     *     RFC9580 - Version 3 Public Key Encrypted Session Key Packet</a>
     */
    public ContainedPacket generateV3(byte[] sessionInfo)
            throws PGPException
    {
        long keyId;
        if (useWildcardRecipient)
        {
            keyId = WILDCARD_KEYID;
        }
        else
        {
            keyId = pubKey.getKeyID();
        }
        byte[] encryptedSessionInfo = encryptSessionInfoV3(pubKey, sessionInfo);
        byte[][] encodedEncSessionInfo = encodeEncryptedSessionInfo(encryptedSessionInfo);
        return PublicKeyEncSessionPacket.createV3PKESKPacket(keyId, pubKey.getAlgorithm(), encodedEncSessionInfo);
    }

    /**
     * Generate a Public-Key Encrypted Session-Key (PKESK) packet of version 6.
     * PKESKv6 packets are used with Symmetrically-Encrypted Integrity-Protected Data (SEIPD) packets
     * of version 2 only.
     * PKESKv6 packets are used with keys that support {@link org.bouncycastle.bcpg.sig.Features#FEATURE_SEIPD_V2}.
     *
     * @param sessionInfo session-key algorithm id + session-key + checksum
     * @return PKESKv6 packet
     *
     * @throws PGPException if the PKESK packet cannot be generated
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-key-encryp">
     *     RFC9580 - Version 6 Public Key Encrypted Session Key Packet</a>
     */
    public ContainedPacket generateV6(byte[] sessionInfo)
        throws PGPException
    {
        byte[] keyFingerprint;
        int keyVersion;
        if (useWildcardRecipient)
        {
            keyFingerprint = WILDCARD_FINGERPRINT;
            keyVersion = 0;
        }
        else
        {
            keyFingerprint = pubKey.getFingerprint();
            keyVersion = pubKey.getVersion();
        }
        byte[] encryptedSessionInfo = encryptSessionInfoV6(pubKey, sessionInfo);
        byte[][] encodedEncSessionInfo = encodeEncryptedSessionInfo(encryptedSessionInfo);
        return PublicKeyEncSessionPacket.createV6PKESKPacket(keyVersion, keyFingerprint, pubKey.getAlgorithm(), encodedEncSessionInfo);
    }

    /**
     * Encrypt a session key using the recipients public key.
     * @param pubKey recipients public key
     * @param fullSessionInfo full session info (sym-alg-id + session-key + 2 octet checksum)
     * @param sessionInfoToEncrypt for v3: full session info; for v6: just the session-key
     * @param optSymAlgId for v3: session key algorithm ID; for v6: empty array
     * @return encrypted session info
     * @throws PGPException
     */
    protected abstract byte[] encryptSessionInfo(PGPPublicKey pubKey,
                                                 byte[] fullSessionInfo,
                                                 byte[] sessionInfoToEncrypt,
                                                 byte[] optSymAlgId)
        throws PGPException;

    /**
     * Encrypt a session key for a v3 PKESK.
     * @param pubKey recipients public key
     * @param sessionInfo session info (sym-alg-id + session-key + 2 octet checksum)
     * @return encrypted session info
     * @throws PGPException
     */
    protected byte[] encryptSessionInfoV3(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        return encryptSessionInfo(pubKey, sessionInfo, sessionInfo, new byte[]{sessionInfo[0]});
    }

    /**
     * Encrypt a session key for a v6 PKESK.
     * @param pubKey recipients public key
     * @param sessionInfo session info (sym-alg-id + session-key + 2 octet checksum)
     * @return encrypted session info
     * @throws PGPException
     */
    protected byte[] encryptSessionInfoV6(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        // In V6, do not include the symmetric-key algorithm in the session-info
        byte[] sessionInfoWithoutAlgId = new byte[sessionInfo.length - 1];
        System.arraycopy(sessionInfo, 1, sessionInfoWithoutAlgId, 0, sessionInfoWithoutAlgId.length);

        return encryptSessionInfo(pubKey, sessionInfo, sessionInfoWithoutAlgId, new byte[0]);
    }

    protected static byte[] concatECDHEphKeyWithWrappedSessionKey(byte[] ephPubEncoding, byte[] wrappedSessionKey)
        throws IOException
    {
        // https://www.rfc-editor.org/rfc/rfc9580.html#section-11.5-16

        byte[] mpiEncodedEphemeralKey = new MPInteger(new BigInteger(1, ephPubEncoding))
                .getEncoded();
        byte[] out = new byte[mpiEncodedEphemeralKey.length + 1 + wrappedSessionKey.length];
        // eph key
        System.arraycopy(mpiEncodedEphemeralKey, 0, out, 0, mpiEncodedEphemeralKey.length);
        // enc session-key len
        out[mpiEncodedEphemeralKey.length] = (byte) wrappedSessionKey.length;
        // enc session-key
        System.arraycopy(wrappedSessionKey, 0, out, mpiEncodedEphemeralKey.length + 1, wrappedSessionKey.length);

        return out;
    }

    private static byte[] getSessionInfo(byte[] ephPubEncoding, int symmetricKeyAlgorithm, byte[] c)
    {
        return getSessionInfo(ephPubEncoding, new byte[]{(byte) symmetricKeyAlgorithm}, c);
    }

    protected static byte[] getSessionInfo(byte[] ephPubEncoding, byte[] optSymKeyAlgorithm, byte[] wrappedSessionKey)
    {
        int len = ephPubEncoding.length + 1 + optSymKeyAlgorithm.length + wrappedSessionKey.length;
        byte[] out = new byte[len];
        // ephemeral pub key
        System.arraycopy(ephPubEncoding, 0, out, 0, ephPubEncoding.length);
        // len of two/one next fields
        out[ephPubEncoding.length] = (byte) (wrappedSessionKey.length + optSymKeyAlgorithm.length);
        // (optional) sym key alg
        System.arraycopy(optSymKeyAlgorithm, 0, out, ephPubEncoding.length + 1, optSymKeyAlgorithm.length);
        // wrapped session key
        System.arraycopy(wrappedSessionKey, 0, out, ephPubEncoding.length + 1 + optSymKeyAlgorithm.length, wrappedSessionKey.length);
        return out;
    }
}
