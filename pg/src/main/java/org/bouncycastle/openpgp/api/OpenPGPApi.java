package org.bouncycastle.openpgp.api;

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

    public abstract OpenPGPV6KeyGenerator generateKey()
            throws PGPException;

    public abstract OpenPGPV6KeyGenerator generateKey(Date creationTime)
            throws PGPException;

    public abstract OpenPGPV6KeyGenerator generateKey(Date creationTime,
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
