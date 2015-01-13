package org.bouncycastle.jcajce;

import java.security.InvalidParameterException;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This class contains extended parameters for PKIX certification path builders.
 * 
 * @see java.security.cert.PKIXBuilderParameters
 */
public class PKIXExtendedBuilderParameters
    implements CertPathParameters
{
    public static class Builder
    {
        private final PKIXExtendedParameters baseParameters;

        private int maxPathLength = 5;
        private Set excludedCerts = new HashSet();

        public Builder(PKIXBuilderParameters baseParameters)
        {
            this.baseParameters = new PKIXExtendedParameters.Builder(baseParameters).build();
            this.maxPathLength = baseParameters.getMaxPathLength();
        }

        public Builder(PKIXExtendedParameters baseParameters)
        {
            this.baseParameters = baseParameters;
        }

        /**
         * Adds excluded certificates which are not used for building a
         * certification path.
         * <p>
         * The given set is cloned to protect it against subsequent modifications.
         *
         * @param excludedCerts The excluded certificates to set.
         */
        public Builder addExcludedCerts(Set excludedCerts)
        {
            this.excludedCerts.addAll(excludedCerts);

            return this;
        }

        /**
         * Sets the maximum number of intermediate non-self-issued certificates in a
         * certification path. The PKIX <code>CertPathBuilder</code> must not
         * build paths longer then this length.
         * <p>
         * A value of 0 implies that the path can only contain a single certificate.
         * A value of -1 does not limit the length. The default length is 5.
         *
         * <p>
         *
         * The basic constraints extension of a CA certificate overrides this value
         * if smaller.
         *
         * @param maxPathLength the maximum number of non-self-issued intermediate
         *            certificates in the certification path
         * @throws java.security.InvalidParameterException if <code>maxPathLength</code> is set
         *             to a value less than -1
         *
         * @see #getMaxPathLength
         */
        public Builder setMaxPathLength(int maxPathLength)
        {
            if (maxPathLength < -1)
            {
                throw new InvalidParameterException("The maximum path "
                        + "length parameter can not be less than -1.");
            }
            this.maxPathLength = maxPathLength;

            return this;
        }

        public PKIXExtendedBuilderParameters build()
        {
            return new PKIXExtendedBuilderParameters(this);
        }
    }

    private final PKIXExtendedParameters baseParameters;
    private final Set excludedCerts;
    private final int maxPathLength;

    private PKIXExtendedBuilderParameters(Builder builder)
    {
        this.baseParameters = builder.baseParameters;
        this.excludedCerts = Collections.unmodifiableSet(builder.excludedCerts);
        this.maxPathLength = builder.maxPathLength;
    }

    public PKIXExtendedParameters getBaseParameters()
    {
        return baseParameters;
    }

    /**
     * Excluded certificates are not used for building a certification path.
     * <p>
     * The returned set is immutable.
     * 
     * @return Returns the excluded certificates.
     */
    public Set getExcludedCerts()
    {
        return excludedCerts;
    }

    /**
     * Returns the value of the maximum number of intermediate non-self-issued
     * certificates in the certification path.
     * 
     * @return the maximum number of non-self-issued intermediate certificates
     *         in the certification path, or -1 if no limit exists.
     */
    public int getMaxPathLength()
    {
        return maxPathLength;
    }

    /**
     * @return this object
     */
    public Object clone()
    {
        return this;
    }
}

