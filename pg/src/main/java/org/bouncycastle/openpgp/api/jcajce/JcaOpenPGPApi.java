package org.bouncycastle.openpgp.api.jcajce;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Implementation of {@link OpenPGPApi} using the JCA/JCE implementation of OpenPGP classes.
 */
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
    public OpenPGPKeyGenerator generateKey(int version)
            throws PGPException
    {
        return new JcaOpenPGPKeyGenerator(version, provider);
    }

    @Override
    public OpenPGPKeyGenerator generateKey(int version, Date creationTime)
            throws PGPException
    {
        return new JcaOpenPGPKeyGenerator(version, creationTime, provider);
    }

    @Override
    public OpenPGPKeyGenerator generateKey(int version, Date creationTime, boolean aeadProtection)
            throws PGPException
    {
        return new JcaOpenPGPKeyGenerator(version, creationTime, aeadProtection, provider);
    }
}
