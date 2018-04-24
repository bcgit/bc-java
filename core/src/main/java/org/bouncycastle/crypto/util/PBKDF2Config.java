package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Integers;

/**
 * Configuration class for a PBKDF using PKCS#5 Scheme 2.
 */
public class PBKDF2Config
    extends PBKDFConfig
{
    /**
     * AlgorithmIdentifier for a PRF using HMac with SHA-1
     */
    public static final AlgorithmIdentifier PRF_SHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    /**
     * AlgorithmIdentifier for a PRF using HMac with SHA-256
     */
    public static final AlgorithmIdentifier PRF_SHA256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE);

    /**
     * AlgorithmIdentifier for a PRF using HMac with SHA-512
     */
    public static final AlgorithmIdentifier PRF_SHA512 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);

    /**
     * AlgorithmIdentifier for a PRF using HMac with SHA3-256
     */
    public static final AlgorithmIdentifier PRF_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE);

    /**
     * AlgorithmIdentifier for a PRF using SHA3-512
     */
    public static final AlgorithmIdentifier PRF_SHA3_512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, DERNull.INSTANCE);

    private static final Map PRFS_SALT = new HashMap();

    static
    {
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA1, Integers.valueOf(20));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA256, Integers.valueOf(32));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA512, Integers.valueOf(64));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA224, Integers.valueOf(28));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA384, Integers.valueOf(48));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, Integers.valueOf(28));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, Integers.valueOf(32));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, Integers.valueOf(48));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, Integers.valueOf(64));
        PRFS_SALT.put(CryptoProObjectIdentifiers.gostR3411Hmac, Integers.valueOf(32));
        PRFS_SALT.put(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256, Integers.valueOf(32));
        PRFS_SALT.put(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512, Integers.valueOf(64));
        PRFS_SALT.put(GMObjectIdentifiers.hmac_sm3, Integers.valueOf(32));
    }

    static int getSaltSize(ASN1ObjectIdentifier algorithm)
    {
        if (!PRFS_SALT.containsKey(algorithm))
        {
            throw new IllegalStateException("no salt size for algorithm: " + algorithm);
        }

        return ((Integer)PRFS_SALT.get(algorithm)).intValue();
    }

    public static class Builder
    {
        private int iterationCount = 1024;
        private int saltLength = -1;
        private AlgorithmIdentifier prf = PRF_SHA1;

        /**
         * Base constructor.
         *
         * This configures the builder to use an iteration count of 1024, and the HMacSHA1 PRF.
         */
        public Builder()
        {
        }

        /**
         * Set the iteration count for the PBE calculation.
         *
         * @param iterationCount the iteration count to apply to the key creation.
         * @return the current builder.
         */
        public Builder withIterationCount(int iterationCount)
        {
            this.iterationCount = iterationCount;

            return this;
        }

        /**
         * Set the PRF to use for key generation. By default this is HmacSHA1.
         *
         * @param prf algorithm id for PRF.
         * @return the current builder.
         */
        public Builder withPRF(AlgorithmIdentifier prf)
        {
            this.prf = prf;

            return this;
        }

        /**
         * Set the length of the salt to use.
         *
         * @param saltLength the length of the salt (in octets) to use.
         * @return the current builder.
         */
        public Builder withSaltLength(int saltLength)
        {
            this.saltLength = saltLength;

            return this;
        }

        public PBKDF2Config build()
        {
            return new PBKDF2Config(this);
        }
    }

    private final int iterationCount;
    private final int saltLength;
    private final AlgorithmIdentifier prf;

    private PBKDF2Config(Builder builder)
    {
        super(PKCSObjectIdentifiers.id_PBKDF2);

        this.iterationCount = builder.iterationCount;
        this.prf = builder.prf;

        if (builder.saltLength < 0)
        {
            this.saltLength = getSaltSize(prf.getAlgorithm());
        }
        else
        {
            this.saltLength = builder.saltLength;
        }
    }

    public int getIterationCount()
    {
        return iterationCount;
    }

    public AlgorithmIdentifier getPRF()
    {
        return prf;
    }

    public int getSaltLength()
    {
        return saltLength;
    }
}
