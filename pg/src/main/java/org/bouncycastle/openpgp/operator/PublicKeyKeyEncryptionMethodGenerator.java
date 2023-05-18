package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Properties;

import java.io.IOException;
import java.math.BigInteger;

public abstract class PublicKeyKeyEncryptionMethodGenerator
    extends PGPKeyEncryptionMethodGenerator
{
    public static final String SESSION_KEY_OBFUSCATION_PROPERTY = "org.bouncycastle.openpgp.session_key_obfuscation";
    public static final long WILDCARD = 0L;

    private static boolean getSessionKeyObfuscationDefault()
    {
        // by default we want this to be true.
        return !Properties.isOverrideSetTo(SESSION_KEY_OBFUSCATION_PROPERTY, false);
    }

    private PGPPublicKey pubKey;

    protected boolean sessionKeyObfuscation;
    protected boolean useWildcardKeyID;

    protected PublicKeyKeyEncryptionMethodGenerator(
        PGPPublicKey pubKey)
    {
        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            break;
        case PGPPublicKey.RSA_SIGN:
            throw new IllegalArgumentException("Can't use an RSA_SIGN key for encryption.");
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            break;
        case PGPPublicKey.ECDH:
            break;
        case PGPPublicKey.DSA:
            throw new IllegalArgumentException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new IllegalArgumentException("Can't use ECDSA for encryption.");
        default:
            throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        this.pubKey = pubKey;
        this.sessionKeyObfuscation = getSessionKeyObfuscationDefault();
    }

    /**
     * Controls whether to obfuscate the size of ECDH session keys using extra padding where necessary.
     * <p>
     * The default behaviour can be configured using the system property "", or else it will default to enabled.
     * </p>
     * @return the current generator.
     */
    public PublicKeyKeyEncryptionMethodGenerator setSessionKeyObfuscation(boolean enabled)
    {
        this.sessionKeyObfuscation = enabled;

        return this;
    }

    /**
     * Controls whether the recipient key ID is hidden (replaced by a wildcard ID <pre>0</pre>).
     *
     * @param enabled boolean
     * @return this
     */
    public PublicKeyKeyEncryptionMethodGenerator setUseWildcardKeyID(boolean enabled)
    {
        this.useWildcardKeyID = enabled;

        return this;
    }

    public byte[][] processSessionInfo(
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

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        long keyId;
        if (useWildcardKeyID)
        {
            keyId = WILDCARD;
        }
        else
        {
            keyId = pubKey.getKeyID();
        }
        return PublicKeyEncSessionPacket.createV3PKESKPacket(keyId, pubKey.getAlgorithm(), processSessionInfo(encryptSessionInfo(pubKey, sessionInfo)));
    }

    @Override
    public ContainedPacket generateV5(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
            throws PGPException
    {
        // TODO: Implement
        return null;
    }

    @Override
    public ContainedPacket generateV6(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
            throws PGPException
    {
        // TODO: Implement
        return null;
    }

    abstract protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException;
}
