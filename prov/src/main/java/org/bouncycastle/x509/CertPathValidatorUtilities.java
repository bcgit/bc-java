package org.bouncycastle.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PKIXPolicyNode;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

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
//    protected static final String FRESHEST_CRL = Extension.freshestCRL.getId();
//    protected static final String CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
//    protected static final String AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();
    protected static final String CRL_NUMBER = Extension.cRLNumber.getId();

    protected static final String ANY_POLICY = "2.5.29.32.0";

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

    /**
     * Returns the issuer of an attribute certificate or certificate.
     *
     * @param cert The attribute certificate or certificate.
     * @return The issuer as <code>X500Principal</code>.
     */
    protected static X500Principal getEncodedIssuerPrincipal(
        Object cert)
    {
        if (cert instanceof X509Certificate)
        {
            return ((X509Certificate)cert).getIssuerX500Principal();
        }
        else
        {
            return (X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0];
        }
    }

    protected static Date getValidityDate(PKIXParameters paramsPKIX, Date currentDate)
    {
        Date validityDate = paramsPKIX.getDate();

        return null == validityDate ? currentDate : validityDate;
    }

    protected static X500Principal getSubjectPrincipal(X509Certificate cert)
    {
        return cert.getSubjectX500Principal();
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
    protected static ASN1Primitive getExtensionValue(
        java.security.cert.X509Extension ext,
        String oid)
        throws AnnotatedException
    {
        byte[] bytes = ext.getExtensionValue(oid);
        if (bytes == null)
        {
            return null;
        }

        return getObject(oid, bytes);
    }

    private static ASN1Primitive getObject(
        String oid,
        byte[] ext)
        throws AnnotatedException
    {
        try
        {
            ASN1InputStream aIn = new ASN1InputStream(ext);
            ASN1OctetString octs = (ASN1OctetString)aIn.readObject();

            aIn = new ASN1InputStream(octs.getOctets());
            return aIn.readObject();
        }
        catch (Exception e)
        {
            throw new AnnotatedException("exception processing extension " + oid, e);
        }
    }

    protected static X500Principal getIssuerPrincipal(X509CRL crl)
    {
        return crl.getIssuerX500Principal();
    }

    protected static AlgorithmIdentifier getAlgorithmIdentifier(
        PublicKey key)
        throws CertPathValidatorException
    {
        try
        {
            ASN1InputStream aIn = new ASN1InputStream(key.getEncoded());

            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

            return info.getAlgorithmId();
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
                node.setExpectedPolicies((Set)m_idp.get(id_p));
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
     * Return a Collection of all certificates or attribute certificates found
     * in the X509Store's that are matching the certSelect criteriums.
     *
     * @param certSelect a {@link Selector} object that will be used to select
     *                   the certificates
     * @param certStores a List containing only {@link X509Store} objects. These
     *                   are used to search for certificates.
     * @return a Collection of all found {@link X509Certificate} or
     *         {@link org.bouncycastle.x509.X509AttributeCertificate} objects.
     *         May be empty but never <code>null</code>.
     */
    protected static Collection findCertificates(X509CertStoreSelector certSelect,
                                                 List certStores)
        throws AnnotatedException
    {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();
        org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory certFact = new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory();

        while (iter.hasNext())
        {
            Object obj = iter.next();

            if (obj instanceof Store)
            {
                Store certStore = (Store)obj;
                try
                {
                    for (Iterator it = certStore.getMatches(certSelect).iterator(); it.hasNext();)
                    {
                        Object cert = it.next();

                        if (cert instanceof Encodable)
                        {
                            certs.add(certFact.engineGenerateCertificate(new ByteArrayInputStream(((Encodable)cert).getEncoded())));
                        }
                        else if (cert instanceof Certificate)
                        {
                             certs.add(cert);
                        }
                        else
                        {
                            throw new AnnotatedException(
                                    "Unknown object found in certificate store.");
                        }
                    }
                }
                catch (StoreException e)
                {
                    throw new AnnotatedException(
                            "Problem while picking certificates from X.509 store.", e);
                }
                catch (IOException e)
                {
                    throw new AnnotatedException(
                            "Problem while extracting certificates from X.509 store.", e);
                }
                catch (CertificateException e)
                {
                    throw new AnnotatedException(
                            "Problem while extracting certificates from X.509 store.", e);
                }
            }
            else
            {
                CertStore certStore = (CertStore)obj;

                try
                {
                    certs.addAll(certStore.getCertificates(certSelect));
                }
                catch (CertStoreException e)
                {
                    throw new AnnotatedException(
                        "Problem while picking certificates from certificate store.",
                        e);
                }
            }
        }
        return certs;
    }

    protected static Collection findCertificates(PKIXCertStoreSelector certSelect,
                                                 List certStores)
        throws AnnotatedException
    {
        Set certs = new HashSet();
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
                    throw new AnnotatedException(
                            "Problem while picking certificates from X.509 store.", e);
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
                    throw new AnnotatedException(
                        "Problem while picking certificates from certificate store.",
                        e);
                }
            }
        }
        return certs;
    }

    protected static Collection findCertificates(X509AttributeCertStoreSelector certSelect,
                                                 List certStores)
        throws AnnotatedException
    {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();

        while (iter.hasNext())
        {
            Object obj = iter.next();

            if (obj instanceof X509Store)
            {
                X509Store certStore = (X509Store)obj;
                try
                {
                    certs.addAll(certStore.getMatches(certSelect));
                }
                catch (StoreException e)
                {
                    throw new AnnotatedException(
                            "Problem while picking certificates from X.509 store.", e);
                }
            }
        }
        return certs;
    }

    private static BigInteger getSerialNumber(
        Object cert)
    {
        if (cert instanceof X509Certificate)
        {
            return ((X509Certificate)cert).getSerialNumber();
        }
        else
        {
            return ((X509AttributeCertificate)cert).getSerialNumber();
        }
    }

    protected static void getCertStatus(
        Date validDate,
        X509CRL crl,
        Object cert,
        CertStatus certStatus)
        throws AnnotatedException
    {
        X509CRLEntry crl_entry = null;

        boolean isIndirect;
        try
        {
            isIndirect = isIndirectCRL(crl);
        }
        catch (CRLException exception)
        {
            throw new AnnotatedException("Failed check for indirect CRL.", exception);
        }

        if (isIndirect)
        {
            crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));

            if (crl_entry == null)
            {
                return;
            }

            X500Principal certIssuer = crl_entry.getCertificateIssuer();

            if (certIssuer == null)
            {
                certIssuer = getIssuerPrincipal(crl);
            }

            if (!getEncodedIssuerPrincipal(cert).equals(certIssuer))
            {
                return;
            }
        }
        else if (!getEncodedIssuerPrincipal(cert).equals(getIssuerPrincipal(crl)))
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
            try
            {
                reasonCode = ASN1Enumerated
                    .getInstance(CertPathValidatorUtilities
                        .getExtensionValue(crl_entry,
                            X509Extension.reasonCode.getId()));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "Reason code CRL entry extension could not be decoded.",
                    e);
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
     * @throws CertPathValidatorException if DSA parameters cannot be inherited.
     */
    protected static PublicKey getNextWorkingKey(List certs, int index)
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
                KeyFactory keyFactory = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
                return keyFactory.generatePublic(dsaPubKeySpec);
            }
            catch (Exception exception)
            {
                throw new RuntimeException(exception.getMessage());
            }
        }
        throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
    }

    protected static void verifyX509Certificate(X509Certificate cert, PublicKey publicKey,
                                                String sigProvider)
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

    static boolean isIndirectCRL(X509CRL crl)
        throws CRLException
    {
        try
        {
            byte[] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
            return idp != null
                && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(idp).getOctets()).isIndirectCRL();
        }
        catch (Exception e)
        {
            throw new CRLException(
                    "Exception reading IssuingDistributionPoint: " + e);
        }
    }
}
