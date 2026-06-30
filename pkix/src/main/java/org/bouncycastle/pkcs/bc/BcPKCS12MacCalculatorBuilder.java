package org.bouncycastle.pkcs.bc;

import java.security.SecureRandom;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;

/**
 * Lightweight builder for the password-based MAC calculator used to protect the integrity of a
 * PKCS#12 PFX (RFC 7292). Defaults to SHA-1 with an iteration count of 1024.
 */
public class BcPKCS12MacCalculatorBuilder
    implements PKCS12MacCalculatorBuilder
{
    private ExtendedDigest digest;
    private AlgorithmIdentifier algorithmIdentifier;

    private SecureRandom  random;
    private int    saltLength;
    private int    iterationCount = 1024;

    /**
     * Default constructor — produces a SHA-1 based MAC builder.
     */
    public BcPKCS12MacCalculatorBuilder()
    {
        this(new SHA1Digest(), new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE));
    }

    /**
     * Construct a MAC builder backed by a specific digest.
     *
     * @param digest              the lightweight digest implementation to drive the HMAC.
     * @param algorithmIdentifier the algorithm identifier describing {@code digest}.
     */
    public BcPKCS12MacCalculatorBuilder(ExtendedDigest digest, AlgorithmIdentifier algorithmIdentifier)
    {
        this.digest = digest;
        this.algorithmIdentifier = algorithmIdentifier;
        this.saltLength = digest.getDigestSize();
    }

    /**
     * Override the iteration count used by the PKCS#12 key derivation. Defaults to 1024.
     *
     * @param iterationCount the iteration count.
     * @return this builder.
     */
    public BcPKCS12MacCalculatorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;

        return this;
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public MacCalculator build(final char[] password)
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        byte[] salt = new byte[saltLength];

        random.nextBytes(salt);

        return PKCS12PBEUtils.createMacCalculator(algorithmIdentifier.getAlgorithm(), digest, new PKCS12PBEParams(salt, iterationCount), password);
    }
}
