package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Configuration class for a PBKDF using PKCS#5 Scheme 2.
 */
public class PBKDF2
    extends PBKDFConfig
{
    public static class Builder
    {
        private int iterationCount = 1024;
        private int saltLength = -1;
        private AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

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

        public PBKDF2 build()
        {
            return new PBKDF2(this);
        }
    }

    private final int iterationCount;
    private final int saltLength;
    private final AlgorithmIdentifier prf;

    private PBKDF2(Builder builder)
    {
        super(PKCSObjectIdentifiers.id_PBKDF2);

        this.iterationCount = builder.iterationCount;
        this.prf = builder.prf;

        if (builder.saltLength < 0)
        {
            this.saltLength = PKCSUtils.getSaltSize(prf.getAlgorithm());
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
