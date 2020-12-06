package org.bouncycastle.pkix.jcajce;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.WeakHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Iterable;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

/**
 * X.509 Certificate Revocation Checker - still lacks OCSP support and support for delta CRLs.
 */
public class X509RevocationChecker
    extends PKIXCertPathChecker
{
    /**
     * This is the default PKIX validity model. Actually there are two variants
     * of this: The PKIX model and the modified PKIX model. The PKIX model
     * verifies that all involved certificates must have been valid at the
     * current time. The modified PKIX model verifies that all involved
     * certificates were valid at the time of signing. Both are indirectly chosen
     * with the {@link PKIXParameters#setDate(Date)} method, so this
     * methods sets the Date when <em>all</em> certificates must have been
     * valid.
     */
    public static final int PKIX_VALIDITY_MODEL = 0;

    /**
     * This model uses the following validity model. Each certificate must have
     * been valid at the moment where is was used. That means the end
     * certificate must have been valid at the time the signature was done. The
     * CA certificate which signed the end certificate must have been valid,
     * when the end certificate was signed. The CA (or Root CA) certificate must
     * have been valid, when the CA certificate was signed and so on. So the
     * {@link PKIXParameters#setDate(Date)} method sets the time, when
     * the <em>end certificate</em> must have been valid. It is used e.g.
     * in the German signature law.
     */
    public static final int CHAIN_VALIDITY_MODEL = 1;

    public static class Builder
    {
        private Set<TrustAnchor> trustAnchors;
        private List<CertStore> crlCertStores = new ArrayList<CertStore>();
        private List<Store<CRL>> crls = new ArrayList<Store<CRL>>();
        private boolean isCheckEEOnly;
        private int validityModel = PKIX_VALIDITY_MODEL;
        private Provider provider;
        private String providerName;
        private boolean canSoftFail;
        private long failLogMaxTime;
        private long failHardMaxTime;

        /**
         * Base constructor.
         *
         * @param trustAnchor the trust anchor our chain should start with.
         */
        public Builder(TrustAnchor trustAnchor)
        {
            this.trustAnchors = Collections.singleton(trustAnchor);
        }

        /**
         * Base constructor.
         *
         * @param trustAnchors a set of potential trust anchors
         */
        public Builder(Set<TrustAnchor> trustAnchors)
        {
            this.trustAnchors = new HashSet<TrustAnchor>(trustAnchors);
        }

        /**
         * Base constructor.
         *
         * @param trustStore a keystore of potential trust anchors
         */
        public Builder(KeyStore trustStore)
            throws KeyStoreException
        {
            this.trustAnchors = new HashSet<TrustAnchor>();

            for (Enumeration en = trustStore.aliases(); en.hasMoreElements(); )
            {
                String alias = (String)en.nextElement();

                if (trustStore.isCertificateEntry(alias))
                {
                    trustAnchors.add(new TrustAnchor((X509Certificate)trustStore.getCertificate(alias), null));
                }
            }
        }

        /**
         * Add a collection of CRLs to the checker.
         *
         * @param crls CRLs to be examined.
         * @return the current builder instance.
         */
        public Builder addCrls(CertStore crls)
        {
            this.crlCertStores.add(crls);

            return this;
        }

        /**
         * Add a collection of CRLs to the checker.
         *
         * @param crls CRLs to be examined.
         * @return the current builder instance.
         */
        public Builder addCrls(Store<CRL> crls)
        {
            this.crls.add(crls);

            return this;
        }

        /**
         * @param isTrue true if only end-entities should be checked, false otherwise.
         * @return the current builder instance.
         */
        public Builder setCheckEndEntityOnly(boolean isTrue)
        {
            this.isCheckEEOnly = isTrue;

            return this;
        }

        /**
         * Configure soft failure if CRLs/OCSP not available. If maxTime is greater than zero
         * it represents the acceptable downtime for any responders or distribution points we
         * are trying to connect to, with downtime measured from the first failure. Initially
         * failures will log at Level.WARNING, once maxTime is exceeded any failures will be
         * logged as Level.SEVERE. Setting maxTime to zero will mean 1 failure will be allowed
         * before failures are logged as severe.
         *
         * @param isTrue true soft failure should be enabled, false otherwise.
         * @param maxTime the time that can pass between the first failure and the most recent.
         * @return the current builder instance.
         */
        public Builder setSoftFail(boolean isTrue, long maxTime)
        {
            this.canSoftFail = isTrue;
            this.failLogMaxTime = maxTime;
            this.failHardMaxTime = -1;

            return this;
        }

        /**
         * Configure soft failure with a hard limit if CRLs/OCSP not available. If maxTime is
         * greater than zero it represents the acceptable downtime for any responders or
         * distribution points we are trying to connect to, with downtime measured from the
         * first failure. Initially failures will log at Level.WARNING, once 75% of maxTime is exceeded
         * any failures will be logged as Level.SEVERE. At maxTime any failures will be treated as hard,
         * setting maxTime to zero will mean 1 failure will be allowed.
         *
         * @param isTrue true soft failure should be enabled, false otherwise.
         * @param maxTime the time that can pass between the first failure and the most recent.
         * @return the current builder instance.
         */
        public Builder setSoftFailHardLimit(boolean isTrue, long maxTime)
        {
            this.canSoftFail = isTrue;
            this.failLogMaxTime = (maxTime * 3) / 4;
            this.failHardMaxTime = maxTime;

            return this;
        }

        /**
         * @param validityModel
         *            The validity model to set.
         * @see #CHAIN_VALIDITY_MODEL
         * @see #PKIX_VALIDITY_MODEL
         */
        public Builder setValidityModel(int validityModel)
        {
            this.validityModel = validityModel;

            return this;
        }

        /**
         * Configure to use the installed provider with name ProviderName.
         *
         * @param provider provider to use.
         * @return the current builder instance.
         */
        public Builder usingProvider(Provider provider)
        {
            this.provider = provider;

            return this;
        }

        /**
         * Configure to use the installed provider with name ProviderName.
         *
         * @param providerName name of the installed provider to use.
         * @return the current builder instance.
         */
        public Builder usingProvider(String providerName)
        {
            this.providerName = providerName;

            return this;
        }

        /**
         * Build a revocation checker conforming to the current builder.
         *
         * @return a new X509RevocationChecker.
         */
        public X509RevocationChecker build()
        {
            return new X509RevocationChecker(this);
        }
    }

    private static Logger LOG = Logger.getLogger(X509RevocationChecker.class.getName());
    private static final Map<GeneralName, WeakReference<X509CRL>> crlCache = Collections.synchronizedMap(
                                                        new WeakHashMap<GeneralName, WeakReference<X509CRL>>());

    private final Map<X500Principal, Long> failures = new HashMap<X500Principal, Long>();
    private final Set<TrustAnchor> trustAnchors;
    private final boolean isCheckEEOnly;
    private final int validityModel;
    private final List<Store<CRL>> crls;
    private final List<CertStore> crlCertStores;
    private final JcaJceHelper helper;
    private final boolean canSoftFail;
    private final long failLogMaxTime;
    private final long failHardMaxTime;

    private Date currentDate;
    private X500Principal workingIssuerName;
    private PublicKey workingPublicKey;
    private X509Certificate signingCert;

    private X509RevocationChecker(Builder bldr)
    {
        this.crls = new ArrayList<Store<CRL>>(bldr.crls);
        this.crlCertStores = new ArrayList<CertStore>(bldr.crlCertStores);
        this.isCheckEEOnly = bldr.isCheckEEOnly;
        this.validityModel = bldr.validityModel;
        this.trustAnchors = bldr.trustAnchors;
        this.canSoftFail = bldr.canSoftFail;
        this.failLogMaxTime = bldr.failLogMaxTime;
        this.failHardMaxTime = bldr.failHardMaxTime;

        if (bldr.provider != null)
        {
            this.helper = new ProviderJcaJceHelper(bldr.provider);
        }
        else if (bldr.providerName != null)
        {
            this.helper = new NamedJcaJceHelper(bldr.providerName);
        }
        else
        {
            this.helper = new DefaultJcaJceHelper();
        }
    }

    public void init(boolean forward)
        throws CertPathValidatorException
    {
        if (forward)
        {
            throw new IllegalArgumentException("forward processing not supported");
        }

        this.currentDate = new Date();
        this.workingIssuerName = null;
    }

    public boolean isForwardCheckingSupported()
    {
        return false;
    }

    public Set<String> getSupportedExtensions()
    {
        return null;
    }

    public void check(Certificate certificate, Collection<String> collection)
        throws CertPathValidatorException
    {
        X509Certificate cert = (X509Certificate)certificate;

        if (isCheckEEOnly && cert.getBasicConstraints() != -1)
        {
            this.workingIssuerName = cert.getSubjectX500Principal();
            this.workingPublicKey = cert.getPublicKey();
            this.signingCert = cert;
            
            return;
        }

        TrustAnchor trustAnchor = null;

        if (workingIssuerName == null)
        {
            this.workingIssuerName = cert.getIssuerX500Principal();

            for (Iterator it = trustAnchors.iterator(); it.hasNext(); )
            {
                TrustAnchor anchor = (TrustAnchor)it.next();

                if (workingIssuerName.equals(anchor.getCA())
                    || workingIssuerName.equals(anchor.getTrustedCert().getSubjectX500Principal()))
                {
                    trustAnchor = anchor;
                }
            }

            if (trustAnchor == null)
            {
                throw new CertPathValidatorException("no trust anchor found for " + workingIssuerName);
            }
            
            this.signingCert = trustAnchor.getTrustedCert();
            this.workingPublicKey = signingCert.getPublicKey();
        }

        List<X500Principal> issuerList = new ArrayList<X500Principal>();

        PKIXExtendedParameters.Builder pkixBuilder;
        try
        {
            PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false);
            pkixParams.setDate(currentDate);

            for (int i = 0; i != crlCertStores.size(); i++)
            {
                if (LOG.isLoggable(Level.INFO))
                {
                    addIssuers(issuerList, crlCertStores.get(i));
                }
                pkixParams.addCertStore(crlCertStores.get(i));
            }

            pkixBuilder = new PKIXExtendedParameters.Builder(pkixParams);
            pkixBuilder.setValidityModel(validityModel);
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException("error setting up baseParams: " + e.getMessage());
        }

        for (int i = 0; i != crls.size(); i++)
        {
            if (LOG.isLoggable(Level.INFO))
            {
                addIssuers(issuerList, crls.get(i));
            }
            pkixBuilder.addCRLStore(new LocalCRLStore(crls.get(i)));
        }

        if (issuerList.isEmpty())
        {
            LOG.log(Level.INFO, "configured with 0 pre-loaded CRLs");
        }
        else
        {
            if (LOG.isLoggable(Level.FINE))
            {
                for (int i = 0; i != issuerList.size(); i++)
                {
                    LOG.log(Level.FINE, "configuring with CRL for issuer \"" + issuerList.get(i) + "\"");
                }
            }
            else
            {
                LOG.log(Level.INFO, "configured with " + issuerList.size() + " pre-loaded CRLs");
            }
        }

        PKIXExtendedParameters pkixParams = pkixBuilder.build();

        Date validityDate = RevocationUtilities.getValidityDate(pkixParams, currentDate);

        try
        {
            checkCRLs(pkixParams, currentDate, validityDate, cert, signingCert, workingPublicKey, new ArrayList(), helper);
        }
        catch (AnnotatedException e)
        {
            throw new CertPathValidatorException(e.getMessage(), e.getCause());
        }
        catch (CRLNotFoundException e)
        {
            if (null == cert.getExtensionValue(Extension.cRLDistributionPoints.getId()))
            {
                throw e;
            }

            CRL crl;
            try
            {
                crl = downloadCRLs(cert.getIssuerX500Principal(), currentDate,
                    RevocationUtilities.getExtensionValue(cert, Extension.cRLDistributionPoints), helper);
            }
            catch(AnnotatedException e1)
            {
                throw new CertPathValidatorException(e.getMessage(), e.getCause());
            }

            if (crl != null)
            {
                try
                {
                    pkixBuilder.addCRLStore(new LocalCRLStore(new CollectionStore<CRL>(Collections.singleton(crl))));

                    pkixParams = pkixBuilder.build();

                    validityDate = RevocationUtilities.getValidityDate(pkixParams, currentDate);

                    checkCRLs(pkixParams, currentDate, validityDate, cert, signingCert, workingPublicKey,
                        new ArrayList(), helper);
                }
                catch(AnnotatedException e1)
                {
                    throw new CertPathValidatorException(e.getMessage(), e.getCause());
                }
            }
            else
            {
                if (!canSoftFail)
                {
                    throw e;
                }

                X500Principal issuer = cert.getIssuerX500Principal();

                Long initial = failures.get(issuer);
                if (initial != null)
                {
                     long period = System.currentTimeMillis() - initial.longValue();
                     if (failHardMaxTime != -1 && failHardMaxTime < period)
                     {
                         throw e;
                     }
                     if (period < failLogMaxTime)
                     {
                         LOG.log(Level.WARNING, "soft failing for issuer: \"" + issuer + "\"");
                     }
                     else
                     {
                         LOG.log(Level.SEVERE, "soft failing for issuer: \"" + issuer + "\"");
                     }
                }
                else
                {
                    failures.put(issuer, System.currentTimeMillis());
                }
            }
        }

        this.signingCert = cert;
        this.workingPublicKey = cert.getPublicKey();
        this.workingIssuerName = cert.getSubjectX500Principal();
    }

    private void addIssuers(final List<X500Principal> issuerList, CertStore certStore)
        throws CertStoreException
    {
        certStore.getCRLs(new X509CRLSelector()
        {
            public boolean match(CRL crl)
            {
                if (!(crl instanceof X509CRL))
                {
                    return false;
                }

                issuerList.add(((X509CRL)crl).getIssuerX500Principal());

                return false;
            }
        });
    }

    private void addIssuers(final List<X500Principal> issuerList, Store<CRL> certStore)
    {
        certStore.getMatches(new Selector<CRL>()
        {
            public boolean match(CRL crl)
            {
                if (!(crl instanceof X509CRL))
                {
                    return false;
                }

                issuerList.add(((X509CRL)crl).getIssuerX500Principal());

                return false;
            }

            public Object clone()
            {
                return this;
            }
        });
    }

    private CRL downloadCRLs(X500Principal issuer, Date currentDate, ASN1Primitive crlDpPrimitive, JcaJceHelper helper)
    {
        CRLDistPoint crlDp = CRLDistPoint.getInstance(crlDpPrimitive);
        DistributionPoint[] points = crlDp.getDistributionPoints();

        for (int i = 0; i != points.length; i++)
        {
            DistributionPoint dp = points[i];

            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
            {
                GeneralName[] names = GeneralNames.getInstance(dpn.getName()).getNames();

                for (int n = 0; n != names.length; n++)
                {
                    GeneralName name = names[n];
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                    {
                        X509CRL crl;

                        WeakReference<X509CRL> crlRef = crlCache.get(name);
                        if (crlRef != null)
                        {
                            crl = crlRef.get();
                            if (crl != null
                                && !currentDate.before(crl.getThisUpdate())
                                && !currentDate.after(crl.getNextUpdate()))
                            {
                                return crl;
                            }
                            crlCache.remove(name); // delete expired/out-of-range entry
                        }

                        URL url = null;
                        try
                        {
                            url = new URL(name.getName().toString());
            
                            CertificateFactory certFact = helper.createCertificateFactory("X.509");

                            InputStream urlStream = url.openStream();

                            crl = (X509CRL)certFact.generateCRL(new BufferedInputStream(urlStream));

                            urlStream.close();

                            LOG.log(Level.INFO, "downloaded CRL from CrlDP " + url + " for issuer \"" + issuer + "\"");

                            crlCache.put(name, new WeakReference<X509CRL>(crl));

                            return crl;
                        }
                        catch (Exception e)
                        {
                            if (LOG.isLoggable(Level.FINE))
                            {
                                LOG.log(Level.FINE, "CrlDP " + url + " ignored: " + e.getMessage(), e);
                            }
                            else
                            {
                                LOG.log(Level.INFO, "CrlDP " + url + " ignored: " + e.getMessage());
                            }
                        }
                    }
                }
            }
        }

        return null;
    }
    
    protected static final String[] crlReasons = new String[]{
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "unknown",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise"};

    static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp,
        Map<GeneralName, PKIXCRLStore> namedCRLStoreMap) throws AnnotatedException
    {
        if (crldp == null)
        {
            return Collections.emptyList();
        }

        DistributionPoint dps[];
        try
        {
            dps = crldp.getDistributionPoints();
        }
        catch (Exception e)
        {
            throw new AnnotatedException("could not read distribution points could not be read", e);
        }

        List<PKIXCRLStore> stores = new ArrayList<PKIXCRLStore>();

        for (int i = 0; i < dps.length; i++)
        {
            DistributionPointName dpn = dps[i].getDistributionPoint();
            // look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
            {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                for (int j = 0; j < genNames.length; j++)
                {
                    PKIXCRLStore store = namedCRLStoreMap.get(genNames[j]);
                    if (store != null)
                    {
                        stores.add(store);
                    }
                }
            }
        }

        return stores;
    }

    /**
     * Checks a certificate if it is revoked.
     *
     * @param pkixParams       PKIX parameters.
     * @param cert             Certificate to check if it is revoked.
     * @param validDate        The date when the certificate revocation status should be
     *                         checked.
     * @param sign             The issuer certificate of the certificate <code>cert</code>.
     * @param workingPublicKey The public key of the issuer certificate <code>sign</code>.
     * @param certPathCerts    The certificates of the certification path.
     * @throws AnnotatedException if the certificate is revoked or the status cannot be checked
     * or some error occurs.
     */
    protected void checkCRLs(
        PKIXExtendedParameters pkixParams,
        Date currentDate,
        Date validityDate,
        X509Certificate cert,
        X509Certificate sign,
        PublicKey workingPublicKey,
        List certPathCerts,
        JcaJceHelper helper)
        throws AnnotatedException, CertPathValidatorException
    {
        CRLDistPoint crldp;
        try
        {
            crldp = CRLDistPoint.getInstance(RevocationUtilities.getExtensionValue(cert, Extension.cRLDistributionPoints));
        }
        catch (Exception e)
        {
            throw new AnnotatedException("cannot read CRL distribution point extension", e);
        }

        CertStatus certStatus = new CertStatus();
        ReasonsMask reasonsMask = new ReasonsMask();
        AnnotatedException lastException = null;
        boolean validCrlFound = false;

        // for each distribution point
        if (crldp != null)
        {
            DistributionPoint dps[];
            try
            {
                dps = crldp.getDistributionPoints();
            }
            catch (Exception e)
            {
                throw new AnnotatedException("cannot read distribution points", e);
            }

            if (dps != null)
            {
                PKIXExtendedParameters.Builder pkixBuilder = new PKIXExtendedParameters.Builder(pkixParams);
                try
                {
                    List extras = getAdditionalStoresFromCRLDistributionPoint(crldp, pkixParams.getNamedCRLStoreMap());
                    for (Iterator it = extras.iterator(); it.hasNext(); )
                    {
                        pkixBuilder.addCRLStore((PKIXCRLStore)it.next());
                    }
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                        "no additional CRL locations could be decoded from CRL distribution point extension", e);
                }

                PKIXExtendedParameters pkixParamsFinal = pkixBuilder.build();
                Date validityDateFinal = RevocationUtilities.getValidityDate(pkixParamsFinal, currentDate);

                for (int i = 0; i < dps.length && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons(); i++)
                {
                    try
                    {
                        RFC3280CertPathUtilities.checkCRL(dps[i], pkixParamsFinal, currentDate, validityDateFinal, cert,
                            sign, workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
                        validCrlFound = true;
                    }
                    catch (AnnotatedException e)
                    {
                        lastException = e;
                    }
                }
            }
        }

        /*
         * If the revocation status has not been determined, repeat the process
         * above with any available CRLs not specified in a distribution point
         * but issued by the certificate issuer.
         */

        if (certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons())
        {
            try
            {
                /*
                 * assume a DP with both the reasons and the cRLIssuer fields
                 * omitted and a distribution point name of the certificate
                 * issuer.
                 */
                X500Principal issuer = cert.getIssuerX500Principal();

                DistributionPoint dp = new DistributionPoint(new DistributionPointName(0, new GeneralNames(
                    new GeneralName(GeneralName.directoryName, X500Name.getInstance(issuer.getEncoded())))), null, null);
                PKIXExtendedParameters pkixParamsClone = (PKIXExtendedParameters)pkixParams.clone();
                RFC3280CertPathUtilities.checkCRL(dp, pkixParamsClone, currentDate, validityDate, cert, sign,
                    workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
                validCrlFound = true;
            }
            catch (AnnotatedException e)
            {
                lastException = e;
            }
        }

        if (!validCrlFound)
        {
            if (lastException instanceof AnnotatedException)
            { 
                throw new CRLNotFoundException("no valid CRL found", lastException);
            }

            throw new CRLNotFoundException("no valid CRL found");
        }
        if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
        {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            String message = "certificate [issuer=\"" + cert.getIssuerX500Principal() + "\",serialNumber="
                                           + cert.getSerialNumber() + ",subject=\"" + cert.getSubjectX500Principal() + "\"] revoked after " + df.format(certStatus.getRevocationDate());
            message += ", reason: " + crlReasons[certStatus.getCertStatus()];
            throw new AnnotatedException(message);
        }
        if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == CertStatus.UNREVOKED)
        {
            certStatus.setCertStatus(CertStatus.UNDETERMINED);
        }
        if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
        {
            throw new AnnotatedException("certificate status could not be determined");
        }
    }

    public Object clone()
    {
        return this;
    }

    private class LocalCRLStore
        implements PKIXCRLStore<CRL>, Iterable<CRL>
    {
        private Collection<CRL> _local;

        /**
         * Basic constructor.
         *
         * @param collection - initial contents for the store, this is copied.
         */
        public LocalCRLStore(Store<CRL> collection)
        {
            _local = new ArrayList<CRL>(collection.getMatches(null));
        }

        /**
         * Return the matches in the collection for the passed in selector.
         *
         * @param selector the selector to match against.
         * @return a possibly empty collection of matching objects.
         */
        public Collection<CRL> getMatches(Selector<CRL> selector)
        {
            if (selector == null)
            {
                return new ArrayList<CRL>(_local);
            }

            List<CRL> col = new ArrayList<CRL>();
            Iterator<CRL> iter = _local.iterator();

            while (iter.hasNext())
            {
                CRL obj = iter.next();

                if (selector.match(obj))
                {
                    col.add(obj);
                }
            }

            return col;
        }

        public Iterator<CRL> iterator()
        {
            return getMatches(null).iterator();
        }
    }
}
