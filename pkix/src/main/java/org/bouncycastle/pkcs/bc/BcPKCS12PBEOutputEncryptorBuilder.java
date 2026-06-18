package org.bouncycastle.pkcs.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * Lightweight builder for an {@link OutputEncryptor} that applies one of the PKCS#12
 * password-based encryption schemes from RFC 7292 Appendix C. Defaults to SHA-1 as the KDF
 * digest with an iteration count of 1024.
 */
public class BcPKCS12PBEOutputEncryptorBuilder
{
    private ExtendedDigest digest;

    private BufferedBlockCipher engine;
    private ASN1ObjectIdentifier algorithm;
    private SecureRandom random;
    private int iterationCount = 1024;

    /**
     * Build an encryptor for the given PKCS#12 PBE algorithm using SHA-1 as the KDF digest.
     *
     * @param algorithm the PKCS#12 PBE algorithm identifier.
     * @param engine    the underlying block cipher to wrap with PKCS#7 padding.
     */
    public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine)
    {
        this(algorithm, engine, new SHA1Digest());
    }

    /**
     * Build an encryptor for the given PKCS#12 PBE algorithm and an explicit KDF digest.
     *
     * @param algorithm the PKCS#12 PBE algorithm identifier.
     * @param engine    the underlying block cipher to wrap with PKCS#7 padding.
     * @param pbeDigest the digest to use inside the PKCS#12 KDF.
     */
    public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine, ExtendedDigest pbeDigest)
    {
        this.algorithm = algorithm;
        this.engine = new PaddedBufferedBlockCipher(engine, new PKCS7Padding());
        this.digest = pbeDigest;
    }

    /**
     * Override the iteration count used by the PKCS#12 KDF. Defaults to 1024.
     *
     * @param iterationCount the iteration count.
     * @return this builder.
     */
    public BcPKCS12PBEOutputEncryptorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;
        return this;
    }

    /**
     * Bind the builder to a password and return a configured {@link OutputEncryptor}.
     *
     * @param password the password used to derive the encryption key.
     * @return an output encryptor parameterised with a freshly generated salt and the configured
     *         iteration count.
     */
    public OutputEncryptor build(final char[] password)
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        final byte[] salt = new byte[20];

        random.nextBytes(salt);

        final PKCS12PBEParams pbeParams = new PKCS12PBEParams(salt, iterationCount);

        CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithm, digest, engine.getBlockSize(), pbeParams, password);

        engine.init(true, params);

        return new OutputEncryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithm, pbeParams);
            }

            public OutputStream getOutputStream(OutputStream out)
            {
                return new CipherOutputStream(out, engine);
            }

            public GenericKey getKey()
            {
                return new GenericKey(new AlgorithmIdentifier(algorithm, pbeParams), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
            }
        };
    }
}
