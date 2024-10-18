package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

public abstract class PGPKeyPairGenerator
{

    protected final Date creationTime;
    protected final int version;
    protected SecureRandom random;

    public PGPKeyPairGenerator(int version, Date creationTime, SecureRandom random)
    {
        this.creationTime = new Date((creationTime.getTime() / 1000) * 1000);
        this.version = version;
        this.random = random;
    }

    /**
     * Generate a primary key.
     * A primary key MUST use a signing-capable public key algorithm.
     *
     * @return primary key pair
     * @throws PGPException
     */
    public PGPKeyPair generatePrimaryKey()
            throws PGPException
    {
        return generateEd25519KeyPair();
    }

    /**
     * Generate an encryption subkey.
     * An encryption subkey MUST use an encryption-capable public key algorithm.
     *
     * @return encryption subkey pair
     * @throws PGPException
     */
    public PGPKeyPair generateEncryptionSubkey()
            throws PGPException
    {
        return generateX25519KeyPair();
    }

    /**
     * Generate a signing subkey.
     * A signing subkey MUST use a signing-capable public key algorithm.
     *
     * @return signing subkey pair
     * @throws PGPException
     */
    public PGPKeyPair generateSigningSubkey()
            throws PGPException
    {
        return generateEd25519KeyPair();
    }

    public PGPKeyPair generateRsaKeyPair(int bitStrength)
            throws PGPException
    {
        return generateRsaKeyPair(BigInteger.valueOf(0x10001), bitStrength);
    }

    public abstract PGPKeyPair generateRsaKeyPair(BigInteger exponent, int bitStrength)
            throws PGPException;

    public abstract PGPKeyPair generateEd25519KeyPair()
            throws PGPException;

    public abstract PGPKeyPair generateEd448KeyPair()
            throws PGPException;

    public abstract PGPKeyPair generateX25519KeyPair()
            throws PGPException;

    public abstract PGPKeyPair generateX448KeyPair()
            throws PGPException;

    public abstract PGPKeyPair generateLegacyEd25519KeyPair()
            throws PGPException;

    public abstract PGPKeyPair generateLegacyX25519KeyPair()
            throws PGPException;
}
