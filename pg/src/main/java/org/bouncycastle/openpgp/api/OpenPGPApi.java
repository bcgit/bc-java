package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;

import java.util.Date;

public abstract class OpenPGPApi
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;

    public OpenPGPApi(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    public OpenPGPApi(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    public OpenPGPKeyReader readKeyOrCertificate()
    {
        return new OpenPGPKeyReader(implementation, policy);
    }

    public OpenPGPKeyGenerator generateKey()
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6);
    }

    public abstract OpenPGPKeyGenerator generateKey(int version)
            throws PGPException;

    public OpenPGPKeyGenerator generateKey(Date creationTime)
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6, creationTime);
    }

    public abstract OpenPGPKeyGenerator generateKey(int version,
                                                    Date creationTime)
            throws PGPException;

    public OpenPGPKeyGenerator generateKey(Date creationTime, boolean aeadProtection)
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6, creationTime, aeadProtection);
    }

    public abstract OpenPGPKeyGenerator generateKey(int version,
                                                    Date creationTime,
                                                    boolean aeadProtection)
            throws PGPException;

    public OpenPGPMessageGenerator signAndOrEncryptMessage()
    {
        return new OpenPGPMessageGenerator(implementation, policy);
    }

    public OpenPGPDetachedSignatureGenerator createDetachedSignature()
    {
        return new OpenPGPDetachedSignatureGenerator(implementation, policy);
    }

    public OpenPGPMessageProcessor decryptAndOrVerifyMessage()
    {
        return new OpenPGPMessageProcessor(implementation, policy);
    }

    public OpenPGPDetachedSignatureProcessor verifyDetachedSignature()
    {
        return new OpenPGPDetachedSignatureProcessor(implementation, policy);
    }

    public OpenPGPKeyEditor editKey(OpenPGPKey key)
    {
        return new OpenPGPKeyEditor(key, implementation, policy);
    }

    public OpenPGPImplementation getImplementation()
    {
        return implementation;
    }
}
