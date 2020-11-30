package org.bouncycastle.pkix.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

class RevocationUtilities
{
    protected static final String ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();

    protected static Date getValidityDate(PKIXExtendedParameters paramsPKIX, Date currentDate)
    {
        Date validityDate = paramsPKIX.getValidityDate();

        return null == validityDate ? currentDate : validityDate;
    }

    /**
     * Extract the value of the given extension, if it exists.
     *
     * @param ext
     *            The extension object.
     * @param oid
     *            The object identifier to obtain.
     * @throws AnnotatedException
     *             if the extension cannot be read.
     */
    protected static ASN1Primitive getExtensionValue(java.security.cert.X509Extension ext, ASN1ObjectIdentifier oid)
        throws AnnotatedException
    {
        byte[] bytes = ext.getExtensionValue(oid.getId());

        return null == bytes ? null : getObject(oid, bytes);
    }

    private static ASN1Primitive getObject(ASN1ObjectIdentifier oid, byte[] ext) throws AnnotatedException
    {
        try
        {
            return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets());
        }
        catch (Exception e)
        {
            throw new AnnotatedException("exception processing extension " + oid, e);
        }
    }

    /**
     * Add to a LinkedHashSet all certificates or attribute certificates found in the X509Store's
     * that are matching the certSelect criteria.
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
            throw new AnnotatedException("Distribution points could not be read.", e);
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
    protected static void getCRLIssuersFromDistributionPoint(DistributionPoint dp, Collection issuerPrincipals,
        X509CRLSelector selector) throws AnnotatedException
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
                        issuers.add(X500Name.getInstance(genNames[j].getName()));
                    }
                    catch (IllegalArgumentException e)
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

    protected static void getCertStatus(Date validDate, X509CRL crl, Object cert, CertStatus certStatus)
        throws AnnotatedException
    {
        boolean isIndirect;
        try
        {
            isIndirect = isIndirectCRL(crl);
        }
        catch (CRLException exception)
        {
            throw new AnnotatedException("Failed check for indirect CRL.", exception);
        }

        X509Certificate x509Cert = (X509Certificate)cert;
        X500Name x509CertIssuer = getIssuer(x509Cert);

        if (!isIndirect)
        {
            X500Name crlIssuer = getIssuer(crl);
            if (!x509CertIssuer.equals(crlIssuer))
            {
                return;
            }
        }

        X509CRLEntry crl_entry = crl.getRevokedCertificate(x509Cert.getSerialNumber());
        if (null == crl_entry)
        {
            return;
        }

        if (isIndirect)
        {
            X500Principal certificateIssuer = crl_entry.getCertificateIssuer();

            X500Name expectedCertIssuer;
            if (null == certificateIssuer)
            {
                expectedCertIssuer = getIssuer(crl);
            }
            else
            {
                expectedCertIssuer = getX500Name(certificateIssuer);
            }

            if (!x509CertIssuer.equals(expectedCertIssuer))
            {
                return;
            }
        }

        int reasonCodeValue = CRLReason.unspecified;

        if (crl_entry.hasExtensions())
        {
            try
            {
                ASN1Primitive extValue = RevocationUtilities.getExtensionValue(crl_entry, Extension.reasonCode);
                ASN1Enumerated reasonCode = ASN1Enumerated.getInstance(extValue);
                if (null != reasonCode)
                {
                    reasonCodeValue = reasonCode.intValueExact();
                }
            }
            catch (Exception e)
            {
                throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", e);
            }
        }

        Date revocationDate = crl_entry.getRevocationDate();

        if (validDate.before(revocationDate))
        {
            switch (reasonCodeValue)
            {
            case CRLReason.unspecified:
            case CRLReason.keyCompromise:
            case CRLReason.cACompromise:
            case CRLReason.aACompromise:
                break;
            default:
                return;
            }
        }

        // (i) or (j)
        certStatus.setCertStatus(reasonCodeValue);
        certStatus.setRevocationDate(revocationDate);
    }

    /**
     * Fetches delta CRLs according to RFC 3280 section 5.2.4.
     *
     * @param validityDate
     *            The date for which the delta CRLs must be valid.
     * @param completeCRL
     *            The complete CRL the delta CRL is for.
     * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
     * @throws AnnotatedException
     *             if an exception occurs while picking the delta CRLs.
     */
    protected static Set getDeltaCRLs(Date validityDate, X509CRL completeCRL, List<CertStore> certStores,
        List<PKIXCRLStore> pkixCrlStores) throws AnnotatedException
    {
        X509CRLSelector baseDeltaSelect = new X509CRLSelector();
        // 5.2.4 (a)
        try
        {
            baseDeltaSelect.addIssuerName(completeCRL.getIssuerX500Principal().getEncoded());
        }
        catch (IOException e)
        {
            throw new AnnotatedException("cannot extract issuer from CRL.", e);
        }

        BigInteger completeCRLNumber = null;
        try
        {
            ASN1Primitive derObject = RevocationUtilities.getExtensionValue(completeCRL, Extension.cRLNumber);
            if (derObject != null)
            {
                completeCRLNumber = ASN1Integer.getInstance(derObject).getPositiveValue();
            }
        }
        catch (Exception e)
        {
            throw new AnnotatedException(
                "cannot extract CRL number extension from CRL", e);
        }

        // 5.2.4 (b)
        byte[] idp;
        try
        {
            idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
        }
        catch (Exception e)
        {
            throw new AnnotatedException("issuing distribution point extension value could not be read", e);
        }

        // 5.2.4 (d)

        baseDeltaSelect.setMinCRLNumber(completeCRLNumber == null ? null : completeCRLNumber
            .add(BigInteger.valueOf(1)));

        PKIXCRLStoreSelector.Builder selBuilder = new PKIXCRLStoreSelector.Builder(baseDeltaSelect);

        selBuilder.setIssuingDistributionPoint(idp);
        selBuilder.setIssuingDistributionPointEnabled(true);

        // 5.2.4 (c)
        selBuilder.setMaxBaseCRLNumber(completeCRLNumber);

        PKIXCRLStoreSelector deltaSelect = selBuilder.build();

        // find delta CRLs
        Set temp = PKIXCRLUtil.findCRLs(deltaSelect, validityDate, certStores, pkixCrlStores);

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

        return null == critical ? false : critical.contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
    }

    /**
     * Fetches complete CRLs according to RFC 3280.
     *
     * @param dp
     *            The distribution point for which the complete CRL
     * @param cert
     *            The <code>X509Certificate</code> for which the CRL should be searched.
     * @return A <code>Set</code> of <code>X509CRL</code>s with complete CRLs.
     * @throws AnnotatedException
     *             if an exception occurs while picking the CRLs or no CRLs are found.
     */
    protected static Set getCompleteCRLs(DistributionPoint dp, Object cert, Date validityDate, List certStores, List crlStores)
        throws AnnotatedException, CRLNotFoundException
    {
        X509CRLSelector baseCrlSelect = new X509CRLSelector();

        try
        {
            Set issuers = new HashSet();
            issuers.add(getIssuer((X509Certificate)cert));

            RevocationUtilities.getCRLIssuersFromDistributionPoint(dp, issuers, baseCrlSelect);
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException(
                "Could not get issuer information from distribution point.", e);
        }

        if (cert instanceof X509Certificate)
        {
            baseCrlSelect.setCertificateChecking((X509Certificate)cert);
        }

        PKIXCRLStoreSelector crlSelect = new PKIXCRLStoreSelector.Builder(baseCrlSelect).setCompleteCRLEnabled(true).build();

        Set crls = PKIXCRLUtil.findCRLs(crlSelect, validityDate, certStores, crlStores);

        checkCRLsNotEmpty(crls, cert);

        return crls;
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

    static void checkCRLsNotEmpty(Set crls, Object cert)
        throws CRLNotFoundException
    {
        if (crls.isEmpty())
        {
//            if (cert instanceof X509AttributeCertificate)
//            {
//                X509AttributeCertificate aCert = (X509AttributeCertificate)cert;
//
//                throw new NoCRLFoundException("No CRLs found for issuer \"" + aCert.getIssuer().getPrincipals()[0] + "\"");
//            }
//            else
            {
                X500Name certIssuer = getIssuer((X509Certificate)cert);

                throw new CRLNotFoundException(
                    "No CRLs found for issuer \"" + RFC4519Style.INSTANCE.toString(certIssuer) + "\"");
            }
        }
    }

    public static boolean isIndirectCRL(X509CRL crl) throws CRLException
    {
        try
        {
            byte[] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
            return idp != null
                && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(idp).getOctets()).isIndirectCRL();
        }
        catch (Exception e)
        {
            throw new CRLException("exception reading IssuingDistributionPoint", e);
        }
    }

    private static X500Name getIssuer(X509Certificate cert)
    {
        return getX500Name(cert.getIssuerX500Principal());
    }

    private static X500Name getIssuer(X509CRL crl)
    {
        return getX500Name(crl.getIssuerX500Principal());
    }

    private static X500Name getX500Name(X500Principal principal)
    {
        return X500Name.getInstance(principal.getEncoded());
    }
}
