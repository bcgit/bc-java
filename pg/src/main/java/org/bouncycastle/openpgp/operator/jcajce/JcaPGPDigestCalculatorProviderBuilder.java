package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

/**
 * A builder for {@link PGPDigestCalculatorProvider} instances that obtain cryptographic primitives
 * using the JCA API.
 * <p>
 * By default digest calculator providers obtained from this builder will use the default JCA
 * algorithm lookup mechanisms (i.e. specifying no provider), but a specific provider can be
 * specified prior to building.
 * </p>
 */
public class JcaPGPDigestCalculatorProviderBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    /**
     * Default constructor.
     */
    public JcaPGPDigestCalculatorProviderBuilder()
    {
    }

    JcaPGPDigestCalculatorProviderBuilder(OperatorHelper helper)
    {
        this.helper = helper;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param provider the JCA provider to use.
     * @return the current builder.
     */
    public JcaPGPDigestCalculatorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param providerName the name of the JCA provider to use.
     * @return the current builder.
     */
    public JcaPGPDigestCalculatorProviderBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    /**
     * Constructs a new PGPDigestCalculatorProvider
     *
     * @return a PGPDigestCalculatorProvider that will use the JCA algorithm lookup strategy
     *         configured on this builder.
     * @throws PGPException if an error occurs constructing the digest calculator provider.
     */
    public PGPDigestCalculatorProvider build()
        throws PGPException
    {
        return new PGPDigestCalculatorProvider()
        {
            public PGPDigestCalculator get(final int algorithm)
                throws PGPException
            {
                final DigestOutputStream stream;
                final MessageDigest dig;

                try
                {
                    dig = helper.createDigest(algorithm);

                    stream = new DigestOutputStream(dig);
                }
                catch (GeneralSecurityException e)
                {
                    throw new PGPException("exception on setup: " + e, e);
                }

                return new PGPDigestCalculator()
                {
                    public int getAlgorithm()
                    {
                        return algorithm;
                    }

                    public OutputStream getOutputStream()
                    {
                        return stream;
                    }

                    public byte[] getDigest()
                    {
                        return stream.getDigest();
                    }

                    public void reset()
                    {
                        dig.reset();
                    }
                };
            }
        };
    }

    private class DigestOutputStream
        extends OutputStream
    {
        private MessageDigest dig;

        DigestOutputStream(MessageDigest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws IOException
        {
           dig.update(bytes);
        }

        public void write(int b)
            throws IOException
        {
           dig.update((byte)b);
        }

        byte[] getDigest()
        {
            return dig.digest();
        }
    }
}
