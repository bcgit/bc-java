package org.bouncycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.PKIXCertStore;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.x509.X509AttributeCertificate;

class CertPathValidatorUtilities
{
    protected static final String CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();
    protected static final String BASIC_CONSTRAINTS = Extension.basicConstraints.getId();
    protected static final String POLICY_MAPPINGS = Extension.policyMappings.getId();
    protected static final String SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();
    protected static final String NAME_CONSTRAINTS = Extension.nameConstraints.getId();
    protected static final String KEY_USAGE = Extension.keyUsage.getId();
    protected static final String INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();
    protected static final String ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();
    protected static final String DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();
    protected static final String POLICY_CONSTRAINTS = Extension.policyConstraints.getId();
    protected static final String FRESHEST_CRL = Extension.freshestCRL.getId();
    protected static final String CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
    protected static final String AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();

    protected static final String ANY_POLICY = "2.5.29.32.0";

    protected static final String CRL_NUMBER = Extension.cRLNumber.getId();

    /*
    * key usage bits
    */
    protected static final int KEY_CERT_SIGN = 5;
    protected static final int CRL_SIGN = 6;

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

    static Collection findTargets(PKIXExtendedBuilderParameters paramsPKIX) throws CertPathBuilderException
    {
        PKIXExtendedParameters baseParams = paramsPKIX.getBaseParameters();
        PKIXCertStoreSelector certSelect = baseParams.getTargetConstraints();
        LinkedHashSet targets = new LinkedHashSet();

        try
        {
            CertPathValidatorUtilities.findCertificates(targets, certSelect, baseParams.getCertificateStores());
            CertPathValidatorUtilities.findCertificates(targets, certSelect, baseParams.getCertStores());
        }
        catch (AnnotatedException e)
        {
            throw new ExtCertPathBuilderException("Error finding target certificate.", e);
        }

        if (!targets.isEmpty())
        {
            return targets;
        }

        Certificate target = certSelect.getCertificate();
        if (null == target)
        {
            throw new CertPathBuilderException("No certificate found matching targetConstraints.");
        }

        return Collections.singleton(target);
    }

    /**
     * Search the given Set of TrustAnchor's for one that is the
     * issuer of the given X509 certificate. Uses the default provider
     * for signature verification.
     *
     * @param cert         the X509 certificate
     * @param trustAnchors a Set of TrustAnchor's
     * @return the <code>TrustAnchor</code> object if found or
     *         <code>null</code> if not.
     * @throws AnnotatedException if a TrustAnchor was found but the signature verification
     * on the given certificate has thrown an exception.
     */
    protected static TrustAnchor findTrustAnchor(
        X509Certificate cert,
        Set trustAnchors)
        throws AnnotatedException
    {
        return findTrustAnchor(cert, trustAnchors, null);
    }

    /**
     * Search the given Set of TrustAnchor's for one that is the
     * issuer of the given X509 certificate. Uses the specified
     * provider for signature verification, or the default provider
     * if null.
     *
     * @param cert         the X509 certificate
     * @param trustAnchors a Set of TrustAnchor's
     * @param sigProvider  the provider to use for signature verification
     * @return the <code>TrustAnchor</code> object if found or
     *         <code>null</code> if not.
     * @throws AnnotatedException if a TrustAnchor was found but the signature verification
     * on the given certificate has thrown an exception.
     */
    protected static TrustAnchor findTrustAnchor(
        X509Certificate cert,
        Set trustAnchors,
        String sigProvider)
        throws AnnotatedException
    {
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;

        X509CertSelector certSelectX509 = new X509CertSelector();

        final X500Principal certIssuerPrincipal = cert.getIssuerX500Principal();
        try
        {
            certSelectX509.setSubject(certIssuerPrincipal.getEncoded());
        }
        catch (IOException e)
        {
            throw new AnnotatedException(e.getMessage(), e);
        }

        X500Name certIssuerName = null;

        Iterator iter = trustAnchors.iterator();
        while (iter.hasNext() && trust == null)
        {
            trust = (TrustAnchor)iter.next();
            if (trust.getTrustedCert() != null)
            {
                if (certSelectX509.match(trust.getTrustedCert()))
                {
                    trustPublicKey = trust.getTrustedCert().getPublicKey();
                }
                else
                {
                    trust = null;
                }
            }
            else if (trust.getCAName() != null
                && trust.getCAPublicKey() != null)
            {
                if (certIssuerName == null)
                {
                    certIssuerName = X500Name.getInstance(certIssuerPrincipal.getEncoded());
                }

                try
                {
                    X500Name caName = X500Name.getInstance(new X500Principal(trust.getCAName()).getEncoded());

                    if (certIssuerName.equals(caName))
                    {
                        trustPublicKey = trust.getCAPublicKey();
                    }
                    else
                    {
                        trust = null;
                    }
                }
                catch (IllegalArgumentException ex)
                {
                    trust = null;
                }
            }
            else
            {
                trust = null;
            }

            if (trustPublicKey != null)
            {
                try
                {
                    verifyX509Certificate(cert, trustPublicKey, sigProvider);
                }
                catch (Exception ex)
                {
                    invalidKeyEx = ex;
                    trust = null;
                    trustPublicKey = null;
                }
            }
        }

        if (trust == null && invalidKeyEx != null)
        {
            throw new AnnotatedException("TrustAnchor found but certificate validation failed.", invalidKeyEx);
        }

        return trust;
    }

    static boolean isIssuerTrustAnchor(
        X509Certificate cert,
        Set trustAnchors,
        String sigProvider)
        throws AnnotatedException
    {
        try
        {
            return findTrustAnchor(cert, trustAnchors, sigProvider) != null;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    static List<PKIXCertStore> getAdditionalStoresFromAltNames(
        byte[] issuerAlternativeName,
        Map<GeneralName, PKIXCertStore> altNameCertStoreMap)
        throws CertificateParsingException
    {
        // if in the IssuerAltName extension an URI
        // is given, add an additional X.509 store
        if (issuerAlternativeName == null)
        {
            return Collections.EMPTY_LIST;
        }

        GeneralNames issuerAltName = GeneralNames.getInstance(ASN1OctetString.getInstance(issuerAlternativeName).getOctets());

        GeneralName[] names = issuerAltName.getNames();
        List  stores = new ArrayList();

        for (int i = 0; i != names.length; i++)
        {
            GeneralName altName = names[i];

            PKIXCertStore altStore = (PKIXCertStore)altNameCertStoreMap.get(altName);
            if (altStore != null)
            {
                stores.add(altStore);
            }
        }

        return stores;
    }

    protected static Date getValidityDate(PKIXExtendedParameters paramsPKIX, Date currentDate)
    {
        Date validityDate = paramsPKIX.getValidityDate();

        return null == validityDate ? currentDate : validityDate;
    }

    protected static boolean isSelfIssued(X509Certificate cert)
    {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }

    /**
     * Extract the value of the given extension, if it exists.
     *
     * @param ext The extension object.
     * @param oid The object identifier to obtain.
     * @throws AnnotatedException if the extension cannot be read.
     */
    protected static ASN1Primitive getExtensionValue(java.security.cert.X509Extension ext, String oid)
        throws AnnotatedException
    {
        byte[] bytes = ext.getExtensionValue(oid);

        return null == bytes ? null : getObject(oid, bytes);
    }

    private static ASN1Primitive getObject(String oid, byte[] ext) throws AnnotatedException
    {
        try
        {
            ASN1OctetString octs = ASN1OctetString.getInstance(ext);

            return ASN1Primitive.fromByteArray(octs.getOctets());
        }
        catch (Exception e)
        {
            throw new AnnotatedException("exception processing extension " + oid, e);
        }
    }

    protected static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey key) throws CertPathValidatorException
    {
        try
        {
            return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm();
        }
        catch (Exception e)
        {
            throw new ExtCertPathValidatorException("Subject public key cannot be decoded.", e);
        }
    }

    // crl checking


    //
    // policy checking
    // 

    protected static final Set getQualifierSet(ASN1Sequence qualifiers)
        throws CertPathValidatorException
    {
        Set pq = new HashSet();

        if (qualifiers == null)
        {
            return pq;
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

        Enumeration e = qualifiers.getObjects();
        while (e.hasMoreElements())
        {
            try
            {
                aOut.writeObject((ASN1Encodable)e.nextElement());

                pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
            }
            catch (IOException ex)
            {
                throw new ExtCertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
            }

            bOut.reset();
        }

        return pq;
    }

    protected static PKIXPolicyNode removePolicyNode(
        PKIXPolicyNode validPolicyTree,
        List[] policyNodes,
        PKIXPolicyNode _node)
    {
        PKIXPolicyNode _parent = (PKIXPolicyNode)_node.getParent();

        if (validPolicyTree == null)
        {
            return null;
        }

        if (_parent == null)
        {
            for (int j = 0; j < policyNodes.length; j++)
            {
                policyNodes[j] = new ArrayList();
            }

            return null;
        }
        else
        {
            _parent.removeChild(_node);
            removePolicyNodeRecurse(policyNodes, _node);

            return validPolicyTree;
        }
    }

    private static void removePolicyNodeRecurse(
        List[] policyNodes,
        PKIXPolicyNode _node)
    {
        policyNodes[_node.getDepth()].remove(_node);

        if (_node.hasChildren())
        {
            Iterator _iter = _node.getChildren();
            while (_iter.hasNext())
            {
                PKIXPolicyNode _child = (PKIXPolicyNode)_iter.next();
                removePolicyNodeRecurse(policyNodes, _child);
            }
        }
    }


    protected static boolean processCertD1i(
        int index,
        List[] policyNodes,
        ASN1ObjectIdentifier pOid,
        Set pq)
    {
        List policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode node = (PKIXPolicyNode)policyNodeVec.get(j);
            Set expectedPolicies = node.getExpectedPolicies();

            if (expectedPolicies.contains(pOid.getId()))
            {
                Set childExpectedPolicies = new HashSet();
                childExpectedPolicies.add(pOid.getId());

                PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(),
                    index,
                    childExpectedPolicies,
                    node,
                    pq,
                    pOid.getId(),
                    false);
                node.addChild(child);
                policyNodes[index].add(child);

                return true;
            }
        }

        return false;
    }

    protected static void processCertD1ii(
        int index,
        List[] policyNodes,
        ASN1ObjectIdentifier _poid,
        Set _pq)
    {
        List policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode _node = (PKIXPolicyNode)policyNodeVec.get(j);

            if (ANY_POLICY.equals(_node.getValidPolicy()))
            {
                Set _childExpectedPolicies = new HashSet();
                _childExpectedPolicies.add(_poid.getId());

                PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(),
                    index,
                    _childExpectedPolicies,
                    _node,
                    _pq,
                    _poid.getId(),
                    false);
                _node.addChild(_child);
                policyNodes[index].add(_child);
                return;
            }
        }
    }

    protected static void prepareNextCertB1(
        int i,
        List[] policyNodes,
        String id_p,
        Map m_idp,
        X509Certificate cert
    )
        throws AnnotatedException, CertPathValidatorException
    {
        boolean idp_found = false;
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                idp_found = true;
                node.expectedPolicies = (Set)m_idp.get(id_p);
                break;
            }
        }

        if (!idp_found)
        {
            nodes_i = policyNodes[i].iterator();
            while (nodes_i.hasNext())
            {
                PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
                if (ANY_POLICY.equals(node.getValidPolicy()))
                {
                    Set pq = null;
                    ASN1Sequence policies = null;
                    try
                    {
                        policies = DERSequence.getInstance(getExtensionValue(cert, CERTIFICATE_POLICIES));
                    }
                    catch (Exception e)
                    {
                        throw new AnnotatedException("Certificate policies cannot be decoded.", e);
                    }
                    Enumeration e = policies.getObjects();
                    while (e.hasMoreElements())
                    {
                        PolicyInformation pinfo = null;

                        try
                        {
                            pinfo = PolicyInformation.getInstance(e.nextElement());
                        }
                        catch (Exception ex)
                        {
                            throw new AnnotatedException("Policy information cannot be decoded.", ex);
                        }
                        if (ANY_POLICY.equals(pinfo.getPolicyIdentifier().getId()))
                        {
                            try
                            {
                                pq = getQualifierSet(pinfo.getPolicyQualifiers());
                            }
                            catch (CertPathValidatorException ex)
                            {
                                throw new ExtCertPathValidatorException(
                                    "Policy qualifier info set could not be built.", ex);
                            }
                            break;
                        }
                    }
                    boolean ci = false;
                    if (cert.getCriticalExtensionOIDs() != null)
                    {
                        ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                    }

                    PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                    if (ANY_POLICY.equals(p_node.getValidPolicy()))
                    {
                        PKIXPolicyNode c_node = new PKIXPolicyNode(
                            new ArrayList(), i,
                            (Set)m_idp.get(id_p),
                            p_node, pq, id_p, ci);
                        p_node.addChild(c_node);
                        policyNodes[i].add(c_node);
                    }
                    break;
                }
            }
        }
    }

    protected static PKIXPolicyNode prepareNextCertB2(
        int i,
        List[] policyNodes,
        String id_p,
        PKIXPolicyNode validPolicyTree)
    {
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                p_node.removeChild(node);
                nodes_i.remove();
                for (int k = (i - 1); k >= 0; k--)
                {
                    List nodes = policyNodes[k];
                    for (int l = 0; l < nodes.size(); l++)
                    {
                        PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
                        if (!node2.hasChildren())
                        {
                            validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
                            if (validPolicyTree == null)
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
        return validPolicyTree;
    }

    protected static boolean isAnyPolicy(
        Set policySet)
    {
        return policySet == null || policySet.contains(ANY_POLICY) || policySet.isEmpty();
    }

    /**
     * Return a Collection of all certificates or attribute certificates found in the X509Store's
     * that are matching the certSelect criteriums.
     *
     * @param certs
     *            a {@link LinkedHashSet} to which the certificates will be added.
     * @param certSelect
     *            a {@link Selector} object that will be used to select the certificates
     * @param certStores
     *            a List containing only {@link Store} objects. These are used to search for
     *            certificates.
     * @return a Collection of all found {@link X509Certificate} May be empty but never
     *         <code>null</code>.
     */
    protected static void findCertificates(LinkedHashSet certs, PKIXCertStoreSelector certSelect, List certStores)
        throws AnnotatedException
    {
        Iterator iter = certStores.iterator();
        while (iter.hasNext())
        {
            Object obj = iter.next();
            if (obj instanceof Store)
            {
                Store certStore = (Store)obj;
                try
                {
                    certs.addAll(certStore.getMatches(certSelect));
                }
                catch (StoreException e)
                {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
                }
            }
            else
            {
                CertStore certStore = (CertStore)obj;
                try
                {
                    certs.addAll(PKIXCertStoreSelector.getCertificates(certSelect, certStore));
                }
                catch (CertStoreException e)
                {
                    throw new AnnotatedException("Problem while picking certificates from certificate store.", e);
                }
            }
        }
    }

    static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(
        CRLDistPoint crldp, Map<GeneralName, PKIXCRLStore> namedCRLStoreMap, Date validDate, JcaJceHelper helper)
        throws AnnotatedException
    {
        if (null == crldp)
        {
            return Collections.EMPTY_LIST;
        }

        DistributionPoint dps[];
        try
        {
            dps = crldp.getDistributionPoints();
        }
        catch (Exception e)
        {
            throw new AnnotatedException("Distribution points could not be read.", e);
        }

        List stores = new ArrayList();

        for (int i = 0; i < dps.length; i++)
        {
            DistributionPointName dpn = dps[i].getDistributionPoint();
            // look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
            {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                for (int j = 0; j < genNames.length; j++)
                {
                    PKIXCRLStore store = (PKIXCRLStore)namedCRLStoreMap.get(genNames[j]);
                    if (store != null)
                    {
                        stores.add(store);
                    }
                }
            }
        }

        // if the named CRL store is empty, and we're told to check with CRLDP
        if (stores.isEmpty() && Properties.isOverrideSet("org.bouncycastle.x509.enableCRLDP"))
        {
            CertificateFactory certFact;
            try
            {
                certFact = helper.createCertificateFactory("X.509");
            }
            catch (Exception e)
            {
                throw new AnnotatedException("cannot create certificate factory: " + e.getMessage(), e);
            }

            for (int i = 0; i < dps.length; i++)
            {
                DistributionPointName dpn = dps[i].getDistributionPoint();
                // look for URIs in fullName
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                    for (int j = 0; j < genNames.length; j++)
                    {
                        GeneralName name = genNames[i];
                        if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                        {
                            try
                            {
                                URI distributionPoint = new URI(((ASN1String)name.getName()).getString());
                                PKIXCRLStore store = CrlCache.getCrl(certFact, validDate, distributionPoint);
                                if (store != null)
                                {
                                    stores.add(store);
                                }
                                break;
                            }
                            catch (Exception e)
                            {
                                // ignore...  TODO: maybe log
                            }
                        }
                    }
                }
            }
        }

        return stores;
    }

    /**
     * Add the CRL issuers from the cRLIssuer field of the distribution point or
     * from the certificate if not given to the issuer criterion of the
     * <code>selector</code>.
     * <p>
     * The <code>issuerPrincipals</code> are a collection with a single
     * <code>X500Name</code> for <code>X509Certificate</code>s.
     * </p>
     * @param dp               The distribution point.
     * @param issuerPrincipals The issuers of the certificate or attribute
     *                         certificate which contains the distribution point.
     * @param selector         The CRL selector.
     * @throws AnnotatedException if an exception occurs while processing.
     * @throws ClassCastException if <code>issuerPrincipals</code> does not
     * contain only <code>X500Name</code>s.
     */
    protected static void getCRLIssuersFromDistributionPoint(
        DistributionPoint dp,
        Collection issuerPrincipals,
        X509CRLSelector selector)
        throws AnnotatedException
    {
        List issuers = new ArrayList();
        // indirect CRL
        if (dp.getCRLIssuer() != null)
        {
            GeneralName genNames[] = dp.getCRLIssuer().getNames();
            // look for a DN
            for (int j = 0; j < genNames.length; j++)
            {
                if (genNames[j].getTagNo() == GeneralName.directoryName)
                {
                    try
                    {
                        issuers.add(X500Name.getInstance(genNames[j].getName().toASN1Primitive().getEncoded()));
                    }
                    catch (IOException e)
                    {
                        throw new AnnotatedException(
                            "CRL issuer information from distribution point cannot be decoded.", e);
                    }
                }
            }
        }
        else
        {
            /*
             * certificate issuer is CRL issuer, distributionPoint field MUST be
             * present.
             */
            if (dp.getDistributionPoint() == null)
            {
                throw new AnnotatedException(
                    "CRL issuer is omitted from distribution point but no distributionPoint field present.");
            }
            // add and check issuer principals
            for (Iterator it = issuerPrincipals.iterator(); it.hasNext(); )
            {
                issuers.add(it.next());
            }
        }
        // TODO: is not found although this should correctly add the rel name. selector of Sun is buggy here or PKI test case is invalid
        // distributionPoint
//        if (dp.getDistributionPoint() != null)
//        {
//            // look for nameRelativeToCRLIssuer
//            if (dp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
//            {
//                // append fragment to issuer, only one
//                // issuer can be there, if this is given
//                if (issuers.size() != 1)
//                {
//                    throw new AnnotatedException(
//                        "nameRelativeToCRLIssuer field is given but more than one CRL issuer is given.");
//                }
//                ASN1Encodable relName = dp.getDistributionPoint().getName();
//                Iterator it = issuers.iterator();
//                List issuersTemp = new ArrayList(issuers.size());
//                while (it.hasNext())
//                {
//                    Enumeration e = null;
//                    try
//                    {
//                        e = ASN1Sequence.getInstance(
//                            new ASN1InputStream(((X500Principal) it.next())
//                                .getEncoded()).readObject()).getObjects();
//                    }
//                    catch (IOException ex)
//                    {
//                        throw new AnnotatedException(
//                            "Cannot decode CRL issuer information.", ex);
//                    }
//                    ASN1EncodableVector v = new ASN1EncodableVector();
//                    while (e.hasMoreElements())
//                    {
//                        v.add((ASN1Encodable) e.nextElement());
//                    }
//                    v.add(relName);
//                    issuersTemp.add(new X500Principal(new DERSequence(v)
//                        .getDEREncoded()));
//                }
//                issuers.clear();
//                issuers.addAll(issuersTemp);
//            }
//        }
        Iterator it = issuers.iterator();
        while (it.hasNext())
        {
            try
            {
                selector.addIssuerName(((X500Name)it.next()).getEncoded());
            }
            catch (IOException ex)
            {
                throw new AnnotatedException(
                    "Cannot decode CRL issuer information.", ex);
            }
        }
    }

    private static BigInteger getSerialNumber(Object cert)
    {
        return ((X509Certificate)cert).getSerialNumber();
    }

    protected static void getCertStatus(
        Date validDate,
        X509CRL crl,
        Object cert,
        CertStatus certStatus)
        throws AnnotatedException
    {
        boolean isIndirect;
        try
        {
            isIndirect = X509CRLObject.isIndirectCRL(crl);
        }
        catch (CRLException exception)
        {
            throw new AnnotatedException("Failed check for indirect CRL.", exception);
        }

        X509CRLEntry crl_entry;
        if (isIndirect)
        {
            crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));

            if (crl_entry == null)
            {
                return;
            }

            X500Principal certificateIssuer = ((X509CRLEntryObject)crl_entry).getCertificateIssuer();

            X500Name certIssuer;
            if (certificateIssuer == null)
            {
                certIssuer = PrincipalUtils.getIssuerPrincipal(crl);
            }
            else
            {
                certIssuer = PrincipalUtils.getX500Name(certificateIssuer);
            }

            if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(certIssuer))
            {
                return;
            }
        }
        else if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(PrincipalUtils.getIssuerPrincipal(crl)))
        {
            return;  // not for our issuer, ignore
        }
        else
        {
            crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));

            if (crl_entry == null)
            {
                return;
            }
        }

        ASN1Enumerated reasonCode = null;
        if (crl_entry.hasExtensions())
        {
            if (crl_entry.hasUnsupportedCriticalExtension())
            {
                throw new AnnotatedException("CRL entry has unsupported critical extensions.");
            }

            try
            {
                reasonCode = ASN1Enumerated
                    .getInstance(CertPathValidatorUtilities.getExtensionValue(crl_entry, Extension.reasonCode.getId()));
            }
            catch (Exception e)
            {
                throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", e);
            }
        }

        int reasonCodeValue = (null == reasonCode)
            ?   CRLReason.unspecified
            :   reasonCode.intValueExact();

        // for reason keyCompromise, caCompromise, aACompromise or unspecified
        if (!(validDate.getTime() < crl_entry.getRevocationDate().getTime())
            || reasonCodeValue == CRLReason.unspecified
            || reasonCodeValue == CRLReason.keyCompromise
            || reasonCodeValue == CRLReason.cACompromise
            || reasonCodeValue == CRLReason.aACompromise)
        {
            // (i) or (j)
            certStatus.setCertStatus(reasonCodeValue);
            certStatus.setRevocationDate(crl_entry.getRevocationDate());
        }
    }

    /**
     * Fetches delta CRLs according to RFC 3280 section 5.2.4.
     *
     * @param validityDate The date for which the delta CRLs must be valid.
     * @param completeCRL The complete CRL the delta CRL is for.
     * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
     * @throws AnnotatedException if an exception occurs while picking the delta
     * CRLs.
     */
    protected static Set getDeltaCRLs(Date validityDate,
                                      X509CRL completeCRL,
                                      List<CertStore> certStores,
                                      List<PKIXCRLStore> pkixCrlStores,
                                      JcaJceHelper helper)
        throws AnnotatedException
    {
        X509CRLSelector baseDeltaSelect = new X509CRLSelector();
        // 5.2.4 (a)
        try
        {
            baseDeltaSelect.addIssuerName(PrincipalUtils.getIssuerPrincipal(completeCRL).getEncoded());
        }
        catch (IOException e)
        {
            throw new AnnotatedException("Cannot extract issuer from CRL.", e);
        }

        BigInteger completeCRLNumber = null;
        try
        {
            ASN1Primitive derObject = CertPathValidatorUtilities.getExtensionValue(completeCRL, CRL_NUMBER);
            if (derObject != null)
            {
                completeCRLNumber = ASN1Integer.getInstance(derObject).getPositiveValue();
            }
        }
        catch (Exception e)
        {
            throw new AnnotatedException(
                "CRL number extension could not be extracted from CRL.", e);
        }

        // 5.2.4 (b)
        byte[] idp;
        try
        {
            idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
        }
        catch (Exception e)
        {
            throw new AnnotatedException("Issuing distribution point extension value could not be read.", e);
        }

        // 5.2.4 (d)

        baseDeltaSelect.setMinCRLNumber(completeCRLNumber == null ? null : completeCRLNumber.add(BigInteger.valueOf(1)));

        PKIXCRLStoreSelector.Builder selBuilder = new PKIXCRLStoreSelector.Builder(baseDeltaSelect);

        selBuilder.setIssuingDistributionPoint(idp);
        selBuilder.setIssuingDistributionPointEnabled(true);

        // 5.2.4 (c)
        selBuilder.setMaxBaseCRLNumber(completeCRLNumber);

        PKIXCRLStoreSelector deltaSelect = selBuilder.build();

        // find delta CRLs
        Set temp = PKIXCRLUtil.findCRLs(deltaSelect, validityDate, certStores, pkixCrlStores);

        // if the named CRL store is empty, and we're told to check with CRLDP
        if (temp.isEmpty() && Properties.isOverrideSet("org.bouncycastle.x509.enableCRLDP"))
        {
            CertificateFactory certFact;
            try
            {
                certFact = helper.createCertificateFactory("X.509");
            }
            catch (Exception e)
            {
                throw new AnnotatedException("cannot create certificate factory: " + e.getMessage(), e);
            }

            CRLDistPoint id = CRLDistPoint.getInstance(idp);
            DistributionPoint[] dps = id.getDistributionPoints();
            for (int i = 0; i < dps.length; i++)
            {
                DistributionPointName dpn = dps[i].getDistributionPoint();
                // look for URIs in fullName
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                    for (int j = 0; j < genNames.length; j++)
                    {
                        GeneralName name = genNames[i];
                        if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                        {
                            try
                            {
                                PKIXCRLStore store = CrlCache.getCrl(certFact, validityDate,
                                    new URI(((ASN1String)name.getName()).getString()));
                                if (store != null)
                                {
                                    temp = PKIXCRLUtil.findCRLs(deltaSelect, validityDate, Collections.EMPTY_LIST,
                                        Collections.singletonList(store));
                                }
                                break;
                            }
                            catch (Exception e)
                            {
                                // ignore...  TODO: maybe log
                            }
                        }
                    }
                }
            }
        }
        
        Set result = new HashSet();

        for (Iterator it = temp.iterator(); it.hasNext(); )
        {
            X509CRL crl = (X509CRL)it.next();

            if (isDeltaCRL(crl))
            {
                result.add(crl);
            }
        }

        return result;
    }

    private static boolean isDeltaCRL(X509CRL crl)
    {
        Set critical = crl.getCriticalExtensionOIDs();

        if (critical == null)
        {
            return false;
        }

        return critical.contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
    }

    /**
     * Fetches complete CRLs according to RFC 3280.
     *
     * @param dp          The distribution point for which the complete CRL
     * @param cert        The <code>X509Certificate</code> for
     *                    which the CRL should be searched.
     * @param currentDate The date for which the delta CRLs must be valid.
     * @param paramsPKIX  The extended PKIX parameters.
     * @return A <code>Set</code> of <code>X509CRL</code>s with complete
     *         CRLs.
     * @throws AnnotatedException if an exception occurs while picking the CRLs
     * or no CRLs are found.
     */
    protected static Set getCompleteCRLs(PKIXCertRevocationCheckerParameters params, DistributionPoint dp, Object cert,
        PKIXExtendedParameters paramsPKIX, Date validityDate)
        throws AnnotatedException, RecoverableCertPathValidatorException
    {
        X509CRLSelector baseCrlSelect = new X509CRLSelector();

        try
        {
            Set issuers = new HashSet();
            issuers.add(PrincipalUtils.getEncodedIssuerPrincipal(cert));

            CertPathValidatorUtilities.getCRLIssuersFromDistributionPoint(dp, issuers, baseCrlSelect);
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Could not get issuer information from distribution point.", e);
        }

        if (cert instanceof X509Certificate)
        {
            baseCrlSelect.setCertificateChecking((X509Certificate)cert);
        }

        PKIXCRLStoreSelector crlSelect = new PKIXCRLStoreSelector.Builder(baseCrlSelect).setCompleteCRLEnabled(true)
            .build();

        Set crls = PKIXCRLUtil.findCRLs(crlSelect, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());

        checkCRLsNotEmpty(params, crls, cert);

        return crls;
    }

    protected static Date getValidCertDateFromValidityModel(Date validityDate, int validityModel, CertPath certPath,
        int index) throws AnnotatedException
    {
        if (PKIXExtendedParameters.CHAIN_VALIDITY_MODEL != validityModel || index <= 0)
        {
            // use given signing/encryption/... time (or current date)
            return validityDate;
        }

        X509Certificate issuedCert = (X509Certificate)certPath.getCertificates().get(index - 1);

        if (index - 1 == 0)
        {
            // use time when cert was issued, if available
            ASN1GeneralizedTime dateOfCertgen = null;
            try
            {
                byte[] extBytes = ((X509Certificate)certPath.getCertificates().get(index - 1))
                    .getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen.getId());
                if (extBytes != null)
                {
                    dateOfCertgen = ASN1GeneralizedTime.getInstance(ASN1Primitive.fromByteArray(extBytes));
                }
            }
            catch (IOException e)
            {
                throw new AnnotatedException("Date of cert gen extension could not be read.");
            }
            catch (IllegalArgumentException e)
            {
                throw new AnnotatedException("Date of cert gen extension could not be read.");
            }
            if (dateOfCertgen != null)
            {
                try
                {
                    return dateOfCertgen.getDate();
                }
                catch (ParseException e)
                {
                    throw new AnnotatedException("Date from date of cert gen extension could not be parsed.", e);
                }
            }
        }

        return issuedCert.getNotBefore();
    }

    /**
     * Return the next working key inheriting DSA parameters if necessary.
     * <p>
     * This methods inherits DSA parameters from the indexed certificate or
     * previous certificates in the certificate chain to the returned
     * <code>PublicKey</code>. The list is searched upwards, meaning the end
     * certificate is at position 0 and previous certificates are following.
     * </p>
     * <p>
     * If the indexed certificate does not contain a DSA key this method simply
     * returns the public key. If the DSA key already contains DSA parameters
     * the key is also only returned.
     * </p>
     *
     * @param certs The certification path.
     * @param index The index of the certificate which contains the public key
     *              which should be extended with DSA parameters.
     * @return The public key of the certificate in list position
     *         <code>index</code> extended with DSA parameters if applicable.
     * @throws AnnotatedException if DSA parameters cannot be inherited.
     */
    protected static PublicKey getNextWorkingKey(List certs, int index, JcaJceHelper helper)
        throws CertPathValidatorException
    {
        Certificate cert = (Certificate)certs.get(index);
        PublicKey pubKey = cert.getPublicKey();
        if (!(pubKey instanceof DSAPublicKey))
        {
            return pubKey;
        }
        DSAPublicKey dsaPubKey = (DSAPublicKey)pubKey;
        if (dsaPubKey.getParams() != null)
        {
            return dsaPubKey;
        }
        for (int i = index + 1; i < certs.size(); i++)
        {
            X509Certificate parentCert = (X509Certificate)certs.get(i);
            pubKey = parentCert.getPublicKey();
            if (!(pubKey instanceof DSAPublicKey))
            {
                throw new CertPathValidatorException(
                    "DSA parameters cannot be inherited from previous certificate.");
            }
            DSAPublicKey prevDSAPubKey = (DSAPublicKey)pubKey;
            if (prevDSAPubKey.getParams() == null)
            {
                continue;
            }
            DSAParams dsaParams = prevDSAPubKey.getParams();
            DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(
                dsaPubKey.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
            try
            {
                KeyFactory keyFactory = helper.createKeyFactory("DSA");
                return keyFactory.generatePublic(dsaPubKeySpec);
            }
            catch (Exception exception)
            {
                throw new RuntimeException(exception.getMessage());
            }
        }
        throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
    }

    /**
     * Find the issuer certificates of a given certificate.
     *
     * @param cert       The certificate for which an issuer should be found.
     * @return A <code>Collection</code> object containing the issuer
     *         <code>X509Certificate</code>s. Never <code>null</code>.
     * @throws AnnotatedException if an error occurs.
     */
    static Collection findIssuerCerts(
        X509Certificate cert,
        List<CertStore> certStores,
        List<PKIXCertStore> pkixCertStores)
        throws AnnotatedException
    {
        X509CertSelector selector = new X509CertSelector();

        try
        {
            selector.setSubject(PrincipalUtils.getIssuerPrincipal(cert).getEncoded());
        }
        catch (Exception e)
        {
            throw new AnnotatedException(
                "Subject criteria for certificate selector to find issuer certificate could not be set.", e);
        }

        try
        {
            byte[] akiExtensionValue = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
            if (akiExtensionValue != null)
            {
                ASN1OctetString aki = ASN1OctetString.getInstance(akiExtensionValue);
                byte[] authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aki.getOctets()).getKeyIdentifier();
                if (authorityKeyIdentifier != null)
                {
                    selector.setSubjectKeyIdentifier(new DEROctetString(authorityKeyIdentifier).getEncoded());
                }
            }
        }
        catch (Exception e)
        {
            // authority key identifier could not be retrieved from target cert, just search without it
        }

        PKIXCertStoreSelector certSelect = new PKIXCertStoreSelector.Builder(selector).build();
        LinkedHashSet certs = new LinkedHashSet();

        try
        {
            CertPathValidatorUtilities.findCertificates(certs, certSelect, certStores);
            CertPathValidatorUtilities.findCertificates(certs, certSelect, pkixCertStores);
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Issuer certificate cannot be searched.", e);
        }

        // issuers cannot be verified because possible DSA inheritance parameters are missing

        return certs;
    }

    protected static void verifyX509Certificate(X509Certificate cert, PublicKey publicKey, String sigProvider)
        throws GeneralSecurityException
    {
        if (sigProvider == null)
        {
            cert.verify(publicKey);
        }
        else
        {
            cert.verify(publicKey, sigProvider);
        }
    }

    static void checkCRLsNotEmpty(PKIXCertRevocationCheckerParameters params, Set crls, Object cert)
        throws RecoverableCertPathValidatorException
    {
        if (crls.isEmpty())
        {
            if (cert instanceof X509AttributeCertificate)
            {
                X509AttributeCertificate aCert = (X509AttributeCertificate)cert;

                throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + aCert.getIssuer().getPrincipals()[0] + "\"", null,
                                params.getCertPath(), params.getIndex());
            }
            else
            {
                X509Certificate xCert = (X509Certificate)cert;

                throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + RFC4519Style.INSTANCE.toString(PrincipalUtils.getIssuerPrincipal(xCert)) + "\"", null,
                    params.getCertPath(), params.getIndex());
            }
        }
    }
}
