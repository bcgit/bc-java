package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

public class JceSessionKeyDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JceSessionKeyDataDecryptorFactoryBuilder()
    {
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public JceSessionKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public JceSessionKeyDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);

        return this;
    }

    public SessionKeyDataDecryptorFactory build(PGPSessionKey sessionKey)
    {
        return new JceSessionKeyDataDecryptorFactory(helper, sessionKey);
    }

    private static class JceSessionKeyDataDecryptorFactory
        implements SessionKeyDataDecryptorFactory
    {
        private final OperatorHelper helper;
        private final JceAEADUtil aeadHelper;
        private final PGPSessionKey sessionKey;

        public JceSessionKeyDataDecryptorFactory(OperatorHelper helper, PGPSessionKey sessionKey)
        {
            this.helper = helper;
            this.aeadHelper = new JceAEADUtil(helper);
            this.sessionKey = sessionKey;
        }

        @Override
        public PGPSessionKey getSessionKey()
        {
            return sessionKey;
        }

        // OpenPGP v4
        @Override
        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException
        {
            return helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }

        // OpenPGP v5
        @Override
        public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
            throws PGPException
        {
            return aeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
        }

        // OpenPGP v6
        @Override
        public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
                throws PGPException
        {
            return aeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
        }
    }
}
