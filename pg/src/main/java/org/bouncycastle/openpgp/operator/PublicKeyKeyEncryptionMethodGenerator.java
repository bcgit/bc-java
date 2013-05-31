package org.bouncycastle.openpgp.operator;

import java.math.BigInteger;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

public abstract class PublicKeyKeyEncryptionMethodGenerator
    extends PGPKeyEncryptionMethodGenerator
{
    private PGPPublicKey pubKey;

    protected PublicKeyKeyEncryptionMethodGenerator(
        PGPPublicKey pubKey)
    {
        this.pubKey = pubKey;

        switch (pubKey.getAlgorithm())
        {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                break;
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                break;
            case PGPPublicKey.DSA:
                throw new IllegalArgumentException("Can't use DSA for encryption.");
            case PGPPublicKey.ECDSA:
                throw new IllegalArgumentException("Can't use ECDSA for encryption.");
            default:
                throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }
    }

    public BigInteger[] processSessionInfo(
        byte[] encryptedSessionInfo)
        throws PGPException
    {
        BigInteger[] data;

        switch (pubKey.getAlgorithm())
        {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                data = new BigInteger[1];

                data[0] = new BigInteger(1, encryptedSessionInfo);
                break;
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                byte[] b1 = new byte[encryptedSessionInfo.length / 2];
                byte[] b2 = new byte[encryptedSessionInfo.length / 2];

                System.arraycopy(encryptedSessionInfo, 0, b1, 0, b1.length);
                System.arraycopy(encryptedSessionInfo, b1.length, b2, 0, b2.length);

                data = new BigInteger[2];
                data[0] = new BigInteger(1, b1);
                data[1] = new BigInteger(1, b2);
                break;
            default:
                throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        return data;
    }

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        return new PublicKeyEncSessionPacket(pubKey.getKeyID(), pubKey.getAlgorithm(), processSessionInfo(encryptSessionInfo(pubKey, sessionInfo)));
    }

    abstract protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException;
}
