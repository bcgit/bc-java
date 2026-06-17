package org.bouncycastle.pkcs.bc;

import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;

/**
 * Lightweight builder for an {@link InputDecryptorProvider} that handles the PKCS#12 password-based
 * encryption schemes from RFC 7292 Appendix C (e.g. {@code pbeWithSHAAnd3-KeyTripleDES-CBC}).
 */
public class BcPKCS12PBEInputDecryptorProviderBuilder
{
    private ExtendedDigest digest;

    /**
     * Default constructor — uses SHA-1 for the PKCS#12 KDF.
     */
    public BcPKCS12PBEInputDecryptorProviderBuilder()
    {
         this(new SHA1Digest());
    }

    /**
     * Construct a builder that uses an explicit digest for the PKCS#12 KDF.
     *
     * @param digest the digest implementation to drive the key derivation.
     */
    public BcPKCS12PBEInputDecryptorProviderBuilder(ExtendedDigest digest)
    {
         this.digest = digest;
    }

    /**
     * Bind the builder to a password and return an {@link InputDecryptorProvider}.
     *
     * @param password the password used to derive the encryption key.
     * @return a configured decryptor provider.
     */
    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
            {
                final PaddedBufferedBlockCipher engine = PKCS12PBEUtils.getEngine(algorithmIdentifier.getAlgorithm());

                PKCS12PBEParams           pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithmIdentifier.getAlgorithm(), digest, engine.getBlockSize(), pbeParams, password);

                engine.init(false, params);

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return algorithmIdentifier;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, engine);
                    }

                    public GenericKey getKey()
                    {
                        return new GenericKey(algorithmIdentifier, PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
                    }
                };
            }
        };

    }
}
