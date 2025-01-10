package org.bouncycastle.openpgp.api.jcajce;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Date;

public class JcaOpenPGPApi
        extends OpenPGPApi
{
    private final Provider provider;

    public JcaOpenPGPApi(Provider provider)
    {
        this(provider, CryptoServicesRegistrar.getSecureRandom());
    }

    public JcaOpenPGPApi(Provider provider, SecureRandom random)
    {
        super(new JcaOpenPGPImplementation(provider, random));
        this.provider = provider;
    }

    public JcaOpenPGPApi(Provider provider, OpenPGPPolicy policy)
    {
        this(provider, CryptoServicesRegistrar.getSecureRandom(), policy);
    }

    public JcaOpenPGPApi(Provider provider, SecureRandom random, OpenPGPPolicy policy)
    {
        super(new JcaOpenPGPImplementation(provider, random), policy);
        this.provider = provider;
    }

    @Override
    public OpenPGPV6KeyGenerator generateKey()
            throws PGPException
    {
        return new JcaOpenPGPV6KeyGenerator(provider);
    }

    @Override
    public OpenPGPV6KeyGenerator generateKey(Date creationTime)
            throws PGPException
    {
        return new JcaOpenPGPV6KeyGenerator(creationTime, provider);
    }

    @Override
    public OpenPGPV6KeyGenerator generateKey(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
            throws PGPException
    {
        return new JcaOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, aeadProtection, provider);
    }
}
