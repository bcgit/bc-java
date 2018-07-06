package org.bouncycastle.gpg.keybox.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaKeyBoxBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    /**
     * Default constructor.
     */
    public JcaKeyBoxBuilder()
    {
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param provider the JCA provider to use.
     * @return the current builder.
     */
    public JcaKeyBoxBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param providerName the name of the JCA provider to use.
     * @return the current builder.
     */
    public JcaKeyBoxBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcaKeyBox build(InputStream input)
        throws NoSuchProviderException, NoSuchAlgorithmException, IOException
    {
        return new JcaKeyBox(input, new JcaKeyFingerprintCalculator(), new JcaBlobVerifier(helper));
    }

    public JcaKeyBox build(byte[] encoding)
        throws NoSuchProviderException, NoSuchAlgorithmException, IOException
    {
        return new JcaKeyBox(encoding, new JcaKeyFingerprintCalculator(), new JcaBlobVerifier(helper));
    }
}
