package org.bouncycastle.jcajce;

import java.security.cert.CertPathParameters;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x509.GeneralName;

/**
 * This class extends the PKIXParameters with a validity model parameter.
 */
public class PKIXExtendedParameters
    implements CertPathParameters
{
    /**
     * This is the default PKIX validity model. Actually there are two variants of this: The PKIX
     * model and the modified PKIX model. The PKIX model verifies that all involved certificates
     * must have been valid at the current time. The modified PKIX model verifies that all involved
     * certificates were valid at the signing time. Both are indirectly chosen with the
     * {@link PKIXParameters#setDate(Date)} method, so this methods sets the Date when <em>all</em>
     * certificates must have been valid.
     */
    public static final int PKIX_VALIDITY_MODEL = 0;

    /**
     * This model uses the following validity model. Each certificate must have been valid at the
     * moment when it was used. That means the end certificate must have been valid at the time the
     * signature was done. The CA certificate which signed the end certificate must have been valid,
     * when the end certificate was signed. The CA (or Root CA) certificate must have been valid
     * when the CA certificate was signed, and so on. So the {@link PKIXParameters#setDate(Date)}
     * method sets the time, when the <em>end certificate</em> must have been valid. It is used e.g.
     * in the German signature law.
     */
    public static final int CHAIN_VALIDITY_MODEL = 1;

    /**
     * Builder for a PKIXExtendedParameters object.
     */
    public static class Builder
    {
        private final PKIXParameters baseParameters;
        private final Date validityDate;
        private final Date date;

        private PKIXCertStoreSelector targetConstraints;
        private List<PKIXCertStore> extraCertStores = new ArrayList<PKIXCertStore>();
        private Map<GeneralName, PKIXCertStore> namedCertificateStoreMap = new HashMap<GeneralName, PKIXCertStore>();
        private List<PKIXCRLStore> extraCRLStores = new ArrayList<PKIXCRLStore>();
        private Map<GeneralName, PKIXCRLStore> namedCRLStoreMap = new HashMap<GeneralName, PKIXCRLStore>();
        private boolean revocationEnabled;
        private int validityModel = PKIX_VALIDITY_MODEL;
        private boolean useDeltas = false;
        private Set<TrustAnchor> trustAnchors;

        public Builder(PKIXParameters baseParameters)
        {
            this.baseParameters = (PKIXParameters)baseParameters.clone();
            CertSelector constraints = baseParameters.getTargetCertConstraints();
            if (constraints != null)
            {
                this.targetConstraints = new PKIXCertStoreSelector.Builder(constraints).build();
            }
            this.validityDate = baseParameters.getDate();
            this.date = (validityDate == null) ? new Date() : validityDate;
            this.revocationEnabled = baseParameters.isRevocationEnabled();
            this.trustAnchors = baseParameters.getTrustAnchors();
        }

        public Builder(PKIXExtendedParameters baseParameters)
        {
            this.baseParameters = baseParameters.baseParameters;
            this.validityDate = baseParameters.validityDate;
            this.date = baseParameters.date;
            this.targetConstraints = baseParameters.targetConstraints;
            this.extraCertStores = new ArrayList<PKIXCertStore>(baseParameters.extraCertStores);
            this.namedCertificateStoreMap = new HashMap<GeneralName, PKIXCertStore>(baseParameters.namedCertificateStoreMap);
            this.extraCRLStores = new ArrayList<PKIXCRLStore>(baseParameters.extraCRLStores);
            this.namedCRLStoreMap = new HashMap<GeneralName, PKIXCRLStore>(baseParameters.namedCRLStoreMap);
            this.useDeltas = baseParameters.useDeltas;
            this.validityModel = baseParameters.validityModel;
            this.revocationEnabled = baseParameters.isRevocationEnabled();
            this.trustAnchors = baseParameters.getTrustAnchors();
        }

        public Builder addCertificateStore(PKIXCertStore store)
        {
            extraCertStores.add(store);

            return this;
        }

        public Builder addNamedCertificateStore(GeneralName issuerAltName, PKIXCertStore store)
        {
            namedCertificateStoreMap.put(issuerAltName, store);

            return this;
        }

        public Builder addCRLStore(PKIXCRLStore store)
        {
            extraCRLStores.add(store);

            return this;
        }

        public Builder addNamedCRLStore(GeneralName issuerAltName, PKIXCRLStore store)
        {
            namedCRLStoreMap.put(issuerAltName, store);

            return this;
        }

        public Builder setTargetConstraints(PKIXCertStoreSelector selector)
        {
            targetConstraints = selector;

            return this;
        }

        /**
         * Sets if delta CRLs should be used for checking the revocation status.
         *
         * @param useDeltas <code>true</code> if delta CRLs should be used.
         */
        public Builder setUseDeltasEnabled(boolean useDeltas)
        {
            this.useDeltas = useDeltas;

            return this;
        }

        /**
         * @param validityModel The validity model to set.
         * @see #CHAIN_VALIDITY_MODEL
         * @see #PKIX_VALIDITY_MODEL
         */
        public Builder setValidityModel(int validityModel)
        {
            this.validityModel = validityModel;

            return this;
        }

        /**
         * Set the trustAnchor to be used with these parameters.
         *
         * @param trustAnchor the trust anchor end-entity and CRLs must be based on.
         * @return the current builder.
         */
        public Builder setTrustAnchor(TrustAnchor trustAnchor)
        {
            this.trustAnchors = Collections.singleton(trustAnchor);

            return this;
        }

        /**
         * Set the set of trustAnchors to be used with these parameters.
         *
         * @param trustAnchors  a set of trustAnchors, one of which a particular end-entity and it's associated CRLs must be based on.
         * @return the current builder.
         */
        public Builder setTrustAnchors(Set<TrustAnchor> trustAnchors)
        {
            this.trustAnchors = trustAnchors;

            return this;
        }

        /**
         * Flag whether or not revocation checking is to be enabled.
         *
         * @param revocationEnabled  true if revocation checking to be enabled, false otherwise.
         */
        public void setRevocationEnabled(boolean revocationEnabled)
        {
            this.revocationEnabled = revocationEnabled;
        }

        public PKIXExtendedParameters build()
        {
            return new PKIXExtendedParameters(this);
        }
    }

    private final PKIXParameters baseParameters;
    private final PKIXCertStoreSelector targetConstraints;
    private final Date validityDate;
    private final Date date;
    private final List<PKIXCertStore> extraCertStores;
    private final Map<GeneralName, PKIXCertStore> namedCertificateStoreMap;
    private final List<PKIXCRLStore> extraCRLStores;
    private final Map<GeneralName, PKIXCRLStore> namedCRLStoreMap;
    private final boolean revocationEnabled;
    private final boolean useDeltas;
    private final int validityModel;
    private final Set<TrustAnchor> trustAnchors;

    private PKIXExtendedParameters(Builder builder)
    {
        this.baseParameters = builder.baseParameters;
        this.validityDate = builder.validityDate;
        this.date = builder.date;
        this.extraCertStores = Collections.unmodifiableList(builder.extraCertStores);
        this.namedCertificateStoreMap = Collections.unmodifiableMap(new HashMap<GeneralName, PKIXCertStore>(builder.namedCertificateStoreMap));
        this.extraCRLStores = Collections.unmodifiableList(builder.extraCRLStores);
        this.namedCRLStoreMap = Collections.unmodifiableMap(new HashMap<GeneralName, PKIXCRLStore>(builder.namedCRLStoreMap));
        this.targetConstraints = builder.targetConstraints;
        this.revocationEnabled = builder.revocationEnabled;
        this.useDeltas = builder.useDeltas;
        this.validityModel = builder.validityModel;
        this.trustAnchors = Collections.unmodifiableSet(builder.trustAnchors);
    }

    public List<PKIXCertStore> getCertificateStores()
    {
        return extraCertStores;
    }


    public Map<GeneralName, PKIXCertStore> getNamedCertificateStoreMap()
    {
        return namedCertificateStoreMap;
    }

    public List<PKIXCRLStore> getCRLStores()
    {
        return extraCRLStores;
    }

    public Map<GeneralName, PKIXCRLStore> getNamedCRLStoreMap()
    {
        return namedCRLStoreMap;
    }

    /**
     * Returns the time at which to check the validity of the certification path. If {@code null},
     * the current time is used.
     *
     * @return the {@code Date}, or {@code null} if not set
     */
    public Date getValidityDate()
    {
        return null == validityDate ? null : new Date(validityDate.getTime());
    }

    /**
     * @deprecated Use 'getValidityDate' instead (which can return null).
     */
    public Date getDate()
    {
        return new Date(date.getTime());
    }

    /**
     * Defaults to <code>false</code>.
     *
     * @return Returns if delta CRLs should be used.
     */
    public boolean isUseDeltasEnabled()
    {
        return useDeltas;
    }

    /**
     * @return Returns the validity model.
     * @see #CHAIN_VALIDITY_MODEL
     * @see #PKIX_VALIDITY_MODEL
     */
    public int getValidityModel()
    {
        return validityModel;
    }

    public Object clone()
    {
        return this;
    }

    /**
     * Returns the required constraints on the target certificate.
     * The constraints are returned as an instance of
     * <code>Selector</code>. If <code>null</code>, no constraints are
     * defined.
     *
     * @return a <code>Selector</code> specifying the constraints on the
     *         target certificate or attribute certificate (or <code>null</code>)
     * @see PKIXCertStoreSelector
     */
    public PKIXCertStoreSelector getTargetConstraints()
    {
        return targetConstraints;
    }

    public Set getTrustAnchors()
    {
        return trustAnchors;
    }

    public Set getInitialPolicies()
    {
        return baseParameters.getInitialPolicies();
    }

    public String getSigProvider()
    {
        return baseParameters.getSigProvider();
    }

    public boolean isExplicitPolicyRequired()
    {
        return baseParameters.isExplicitPolicyRequired();
    }

    public boolean isAnyPolicyInhibited()
    {
        return baseParameters.isAnyPolicyInhibited();
    }

    public boolean isPolicyMappingInhibited()
    {
        return baseParameters.isPolicyMappingInhibited();
    }

    public List getCertPathCheckers()
    {
        return baseParameters.getCertPathCheckers();
    }

    public List<CertStore> getCertStores()
    {
        return baseParameters.getCertStores();
    }

    public boolean isRevocationEnabled()
    {
        return revocationEnabled;
    }

    public boolean getPolicyQualifiersRejected()
    {
        return baseParameters.getPolicyQualifiersRejected();
    }
}
