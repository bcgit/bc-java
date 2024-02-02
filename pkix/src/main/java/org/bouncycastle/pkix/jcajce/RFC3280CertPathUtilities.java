package org.bouncycastle.pkix.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;

class RFC3280CertPathUtilities
{
    /**
     * If the complete CRL includes an issuing distribution point (IDP) CRL
     * extension check the following:
     * <p>
     * (i) If the distribution point name is present in the IDP CRL extension
     * and the distribution field is present in the DP, then verify that one of
     * the names in the IDP matches one of the names in the DP. If the
     * distribution point name is present in the IDP CRL extension and the
     * distribution field is omitted from the DP, then verify that one of the
     * names in the IDP matches one of the names in the cRLIssuer field of the
     * DP.
     * </p>
     * <p>
     * (ii) If the onlyContainsUserCerts boolean is asserted in the IDP CRL
     * extension, verify that the certificate does not include the basic
     * constraints extension with the cA boolean asserted.
     * </p>
     * <p>
     * (iii) If the onlyContainsCACerts boolean is asserted in the IDP CRL
     * extension, verify that the certificate includes the basic constraints
     * extension with the cA boolean asserted.
     * </p>
     * <p>
     * (iv) Verify that the onlyContainsAttributeCerts boolean is not asserted.
     * </p>
     *
     * @param dp   The distribution point.
     * @param cert The certificate.
     * @param crl  The CRL.
     * @throws AnnotatedException if one of the conditions is not met or an error occurs.
     */
    protected static void processCRLB2(
        DistributionPoint dp,
        Object cert,
        X509CRL crl)
        throws AnnotatedException
    {
        IssuingDistributionPoint idp = null;
        try
        {
            idp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(crl,
                Extension.issuingDistributionPoint));
        }
        catch (Exception e)
        {
            throw new AnnotatedException("Issuing distribution point extension could not be decoded.", e);
        }
        // (b) (2) (i)
        // distribution point name is present
        if (idp != null)
        {
            if (idp.getDistributionPoint() != null)
            {
                // make list of names
                DistributionPointName dpName = IssuingDistributionPoint.getInstance(idp).getDistributionPoint();
                List names = new ArrayList();

                if (dpName.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(dpName.getName()).getNames();
                    for (int j = 0; j < genNames.length; j++)
                    {
                        names.add(genNames[j]);
                    }
                }
                if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
                {
                    ASN1EncodableVector vec = new ASN1EncodableVector();
                    try
                    {
                        Enumeration e = ASN1Sequence.getInstance(crl.getIssuerX500Principal().getEncoded()).getObjects();
                        while (e.hasMoreElements())
                        {
                            vec.add((ASN1Encodable)e.nextElement());
                        }
                    }
                    catch (Exception e)
                    {
                        throw new AnnotatedException("Could not read CRL issuer.", e);
                    }
                    vec.add(dpName.getName());
                    names.add(new GeneralName(X500Name.getInstance(new DERSequence(vec))));
                }
                boolean matches = false;
                // verify that one of the names in the IDP matches one
                // of the names in the DP.
                if (dp.getDistributionPoint() != null)
                {
                    dpName = dp.getDistributionPoint();
                    GeneralName[] genNames = null;
                    if (dpName.getType() == DistributionPointName.FULL_NAME)
                    {
                        genNames = GeneralNames.getInstance(dpName.getName()).getNames();
                    }
                    if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
                    {
                        if (dp.getCRLIssuer() != null)
                        {
                            genNames = dp.getCRLIssuer().getNames();
                        }
                        else
                        {
                            genNames = new GeneralName[1];
                            try
                            {
                                genNames[0] = new GeneralName(X500Name.getInstance(((X509Certificate)cert).getIssuerX500Principal().getEncoded()));
                            }
                            catch (Exception e)
                            {
                                throw new AnnotatedException("Could not read certificate issuer.", e);
                            }
                        }
                        for (int j = 0; j < genNames.length; j++)
                        {
                            Enumeration e = ASN1Sequence.getInstance(genNames[j].getName().toASN1Primitive()).getObjects();
                            ASN1EncodableVector vec = new ASN1EncodableVector();
                            while (e.hasMoreElements())
                            {
                                vec.add((ASN1Encodable)e.nextElement());
                            }
                            vec.add(dpName.getName());
                            genNames[j] = new GeneralName(X500Name.getInstance(new DERSequence(vec)));
                        }
                    }
                    if (genNames != null)
                    {
                        for (int j = 0; j < genNames.length; j++)
                        {
                            if (names.contains(genNames[j]))
                            {
                                matches = true;
                                break;
                            }
                        }
                    }
                    if (!matches)
                    {
                        throw new AnnotatedException(
                            "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
                    }
                }
                // verify that one of the names in
                // the IDP matches one of the names in the cRLIssuer field of
                // the DP
                else
                {
                    if (dp.getCRLIssuer() == null)
                    {
                        throw new AnnotatedException("Either the cRLIssuer or the distributionPoint field must "
                            + "be contained in DistributionPoint.");
                    }
                    GeneralName[] genNames = dp.getCRLIssuer().getNames();
                    for (int j = 0; j < genNames.length; j++)
                    {
                        if (names.contains(genNames[j]))
                        {
                            matches = true;
                            break;
                        }
                    }
                    if (!matches)
                    {
                        throw new AnnotatedException(
                            "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
                    }
                }
            }
            BasicConstraints bc = null;
            try
            {
                bc = BasicConstraints.getInstance(RevocationUtilities.getExtensionValue((X509Extension)cert,
                    Extension.basicConstraints));
            }
            catch (Exception e)
            {
                throw new AnnotatedException("Basic constraints extension could not be decoded.", e);
            }

            if (cert instanceof X509Certificate)
            {
                // (b) (2) (ii)
                if (idp.onlyContainsUserCerts() && (bc != null && bc.isCA()))
                {
                    throw new AnnotatedException("CA Cert CRL only contains user certificates.");
                }

                // (b) (2) (iii)
                if (idp.onlyContainsCACerts() && (bc == null || !bc.isCA()))
                {
                    throw new AnnotatedException("End CRL only contains CA certificates.");
                }
            }

            // (b) (2) (iv)
            if (idp.onlyContainsAttributeCerts())
            {
                throw new AnnotatedException("onlyContainsAttributeCerts boolean is asserted.");
            }
        }
    }

    /**
     * If the DP includes cRLIssuer, then verify that the issuer field in the
     * complete CRL matches cRLIssuer in the DP and that the complete CRL
     * contains an issuing distribution point extension with the indirectCRL
     * boolean asserted. Otherwise, verify that the CRL issuer matches the
     * certificate issuer.
     *
     * @param dp   The distribution point.
     * @param cert The certificate ot attribute certificate.
     * @param crl  The CRL for <code>cert</code>.
     * @throws AnnotatedException if one of the above conditions does not apply or an error
     *                            occurs.
     */
    protected static void processCRLB1(
        DistributionPoint dp,
        Object cert,
        X509CRL crl)
        throws AnnotatedException
    {
        ASN1Primitive idp = RevocationUtilities.getExtensionValue(crl, Extension.issuingDistributionPoint);
        boolean isIndirect = false;
        if (idp != null)
        {
            if (IssuingDistributionPoint.getInstance(idp).isIndirectCRL())
            {
                isIndirect = true;
            }
        }
        byte[] issuerBytes;

            issuerBytes = crl.getIssuerX500Principal().getEncoded();


        boolean matchIssuer = false;
        if (dp.getCRLIssuer() != null)
        {
            GeneralName genNames[] = dp.getCRLIssuer().getNames();
            for (int j = 0; j < genNames.length; j++)
            {
                if (genNames[j].getTagNo() == GeneralName.directoryName)
                {
                    try
                    {
                        if (Arrays.areEqual(genNames[j].getName().toASN1Primitive().getEncoded(), issuerBytes))
                        {
                            matchIssuer = true;
                        }
                    }
                    catch (IOException e)
                    {
                        throw new AnnotatedException(
                            "CRL issuer information from distribution point cannot be decoded.", e);
                    }
                }
            }
            if (matchIssuer && !isIndirect)
            {
                throw new AnnotatedException("Distribution point contains cRLIssuer field but CRL is not indirect.");
            }
            if (!matchIssuer)
            {
                throw new AnnotatedException("CRL issuer of CRL does not match CRL issuer of distribution point.");
            }
        }
        else
        {
            if (crl.getIssuerX500Principal().equals(((X509Certificate)cert).getIssuerX500Principal()))
            {
                matchIssuer = true;
            }
        }
        if (!matchIssuer)
        {
            throw new AnnotatedException("Cannot find matching CRL issuer for certificate.");
        }
    }

    protected static ReasonsMask processCRLD(
        X509CRL crl,
        DistributionPoint dp)
        throws AnnotatedException
    {
        IssuingDistributionPoint idp = null;
        try
        {
            idp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(crl,
                Extension.issuingDistributionPoint));
        }
        catch (Exception e)
        {
            throw new AnnotatedException("Issuing distribution point extension could not be decoded.", e);
        }
        // (d) (1)
        if (idp != null && idp.getOnlySomeReasons() != null && dp.getReasons() != null)
        {
            return new ReasonsMask(dp.getReasons()).intersect(new ReasonsMask(idp.getOnlySomeReasons()));
        }
        // (d) (4)
        if ((idp == null || idp.getOnlySomeReasons() == null) && dp.getReasons() == null)
        {
            return ReasonsMask.allReasons;
        }
        // (d) (2) and (d)(3)
        return (dp.getReasons() == null
            ? ReasonsMask.allReasons
            : new ReasonsMask(dp.getReasons())).intersect(idp == null
            ? ReasonsMask.allReasons
            : new ReasonsMask(idp.getOnlySomeReasons()));

    }


    public static final String ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();

    public static final String FRESHEST_CRL = Extension.freshestCRL.getId();

    public static final String DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();

    public static final String BASIC_CONSTRAINTS = Extension.basicConstraints.getId();

    public static final String AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();

    /*
     * key usage bits
     */
    protected static final int KEY_CERT_SIGN = 5;

    protected static final int CRL_SIGN = 6;

    /**
     * Obtain and validate the certification path for the complete CRL issuer.
     * If a key usage extension is present in the CRL issuer's certificate,
     * verify that the cRLSign bit is set.
     *
     * @param crl                CRL which contains revocation information for the certificate
     *                           <code>cert</code>.
     * @param cert               The attribute certificate or certificate to check if it is
     *                           revoked.
     * @param defaultCRLSignCert The issuer certificate of the certificate <code>cert</code>.
     * @param defaultCRLSignKey  The public key of the issuer certificate
     *                           <code>defaultCRLSignCert</code>.
     * @param paramsPKIX         PKIX parameters.
     * @param certPathCerts      The certificates on the certification path.
     * @return A <code>Set</code> with all keys of possible CRL issuer
     *         certificates.
     * @throws AnnotatedException if the CRL is not valid or the status cannot be checked or
     *                            some error occurs.
     */
    protected static Set processCRLF(
        X509CRL crl,
        Object cert,
        X509Certificate defaultCRLSignCert,
        PublicKey defaultCRLSignKey,
        PKIXExtendedParameters paramsPKIX,
        List certPathCerts,
        JcaJceHelper helper)
        throws AnnotatedException
    {
        // (f)

        // get issuer from CRL
        X509CertSelector certSelector = new X509CertSelector();
        try
        {
            byte[] issuerPrincipal = crl.getIssuerX500Principal().getEncoded();
            certSelector.setSubject(issuerPrincipal);
        }
        catch (IOException e)
        {
            throw new AnnotatedException(
                "subject criteria for certificate selector to find issuer certificate for CRL could not be set", e);
        }

        PKIXCertStoreSelector selector = new PKIXCertStoreSelector.Builder(certSelector).build();

        // get CRL signing certs
        LinkedHashSet coll = new LinkedHashSet();
        try
        {
            RevocationUtilities.findCertificates(coll, selector, paramsPKIX.getCertificateStores());
            RevocationUtilities.findCertificates(coll, selector, paramsPKIX.getCertStores());
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Issuer certificate for CRL cannot be searched.", e);
        }

        coll.add(defaultCRLSignCert);

        List validCerts = new ArrayList();
        List validKeys = new ArrayList();

        Iterator cert_it = coll.iterator();
        while (cert_it.hasNext())
        {
            X509Certificate signingCert = (X509Certificate)cert_it.next();

            /*
             * CA of the certificate, for which this CRL is checked, has also
             * signed CRL, so skip the path validation, because is already done
             */
            if (signingCert.equals(defaultCRLSignCert))
            {
                validCerts.add(signingCert);
                validKeys.add(defaultCRLSignKey);
                continue;
            }
            try
            {
                CertPathBuilder builder = helper.createCertPathBuilder("PKIX");
                X509CertSelector tmpCertSelector = new X509CertSelector();
                tmpCertSelector.setCertificate(signingCert);

                PKIXExtendedParameters.Builder paramsBuilder = new PKIXExtendedParameters.Builder(paramsPKIX)
                    .setTargetConstraints(new PKIXCertStoreSelector.Builder(tmpCertSelector).build());

                /*
                 * if signingCert is placed not higher on the cert path a
                 * dependency loop results. CRL for cert is checked, but
                 * signingCert is needed for checking the CRL which is dependent
                 * on checking cert because it is higher in the cert path and so
                 * signing signingCert transitively. so, revocation is disabled,
                 * forgery attacks of the CRL are detected in this outer loop
                 * for all other it must be enabled to prevent forgery attacks
                 */
                if (certPathCerts.contains(signingCert))
                {
                    paramsBuilder.setRevocationEnabled(false);
                }
                else
                {
                    paramsBuilder.setRevocationEnabled(true);
                }

                PKIXExtendedBuilderParameters extParams = new PKIXExtendedBuilderParameters.Builder(paramsBuilder.build()).build();

                List certs = builder.build(extParams).getCertPath().getCertificates();
                validCerts.add(signingCert);
                validKeys.add(RevocationUtilities.getNextWorkingKey(certs, 0, helper));
            }
            catch (CertPathBuilderException e)
            {
                throw new AnnotatedException("CertPath for CRL signer failed to validate.", e);
            }
            catch (CertPathValidatorException e)
            {
                throw new AnnotatedException("Public key of issuer certificate of CRL could not be retrieved.", e);
            }
            catch (Exception e)
            {
                throw new AnnotatedException(e.getMessage());
            }
        }

        Set checkKeys = new HashSet();

        AnnotatedException lastException = null;
        for (int i = 0; i < validCerts.size(); i++)
        {
            X509Certificate signCert = (X509Certificate)validCerts.get(i);
            boolean[] keyUsage = signCert.getKeyUsage();

            if (keyUsage != null && (keyUsage.length <= CRL_SIGN || !keyUsage[CRL_SIGN]))
            {
                lastException = new AnnotatedException(
                    "Issuer certificate key usage extension does not permit CRL signing.");
            }
            else
            {
                checkKeys.add(validKeys.get(i));
            }
        }

        if (checkKeys.isEmpty() && lastException == null)
        {
            throw new AnnotatedException("Cannot find a valid issuer certificate.");
        }
        if (checkKeys.isEmpty() && lastException != null)
        {
            throw lastException;
        }

        return checkKeys;
    }

    protected static PublicKey processCRLG(
        X509CRL crl,
        Set keys)
        throws AnnotatedException
    {
        Exception lastException = null;
        for (Iterator it = keys.iterator(); it.hasNext();)
        {
            PublicKey key = (PublicKey)it.next();
            try
            {
                crl.verify(key);
                return key;
            }
            catch (Exception e)
            {
                lastException = e;
            }
        }
        throw new AnnotatedException("Cannot verify CRL.", lastException);
    }

    protected static X509CRL processCRLH(
        Set deltacrls,
        PublicKey key)
        throws AnnotatedException
    {
        Exception lastException = null;

        for (Iterator it = deltacrls.iterator(); it.hasNext();)
        {
            X509CRL crl = (X509CRL)it.next();
            try
            {
                crl.verify(key);
                return crl;
            }
            catch (Exception e)
            {
                lastException = e;
            }
        }

        if (lastException != null)
        {
            throw new AnnotatedException("Cannot verify delta CRL.", lastException);
        }
        return null;
    }

    protected static Set processCRLA1i(
        PKIXExtendedParameters paramsPKIX,
        Date currentDate,
        X509Certificate cert,
        X509CRL crl)
        throws AnnotatedException
    {
        Set set = new HashSet();
        if (paramsPKIX.isUseDeltasEnabled())
        {
            CRLDistPoint freshestCRL = null;
            try
            {
                freshestCRL = CRLDistPoint
                    .getInstance(RevocationUtilities.getExtensionValue(cert, Extension.freshestCRL));
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException("Freshest CRL extension could not be decoded from certificate.", e);
            }
            if (freshestCRL == null)
            {
                try
                {
                    freshestCRL = CRLDistPoint.getInstance(RevocationUtilities.getExtensionValue(crl,
                        Extension.freshestCRL));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException("Freshest CRL extension could not be decoded from CRL.", e);
                }
            }
            if (freshestCRL != null)
            {
                List crlStores = new ArrayList();

                crlStores.addAll(paramsPKIX.getCRLStores());

                try
                {
                    crlStores.addAll(RevocationUtilities.getAdditionalStoresFromCRLDistributionPoint(freshestCRL, paramsPKIX.getNamedCRLStoreMap()));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                        "No new delta CRL locations could be added from Freshest CRL extension.", e);
                }

                // get delta CRL(s)
                try
                {
                    set.addAll(RevocationUtilities.getDeltaCRLs(currentDate, crl, paramsPKIX.getCertStores(), crlStores));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException("Exception obtaining delta CRLs.", e);
                }
            }
        }
        return set;
    }

    protected static Set[] processCRLA1ii(
        PKIXExtendedParameters paramsPKIX,
        Date currentDate,
        Date validityDate,
        X509Certificate cert,
        X509CRL crl)
        throws AnnotatedException
    {
        X509CRLSelector crlselect = new X509CRLSelector();
        crlselect.setCertificateChecking(cert);

        try
        {
            crlselect.addIssuerName(crl.getIssuerX500Principal().getEncoded());
        }
        catch (IOException e)
        {
            throw new AnnotatedException("Cannot extract issuer from CRL." + e, e);
        }

        PKIXCRLStoreSelector extSelect = new PKIXCRLStoreSelector.Builder(crlselect).setCompleteCRLEnabled(true).build();

        Set completeSet = PKIXCRLUtil.findCRLs(extSelect, validityDate, paramsPKIX.getCertStores(),
            paramsPKIX.getCRLStores());
        Set deltaSet = new HashSet();

        if (paramsPKIX.isUseDeltasEnabled())
        {
            // get delta CRL(s)
            try
            {
                deltaSet.addAll(RevocationUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores()));
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException("Exception obtaining delta CRLs.", e);
            }
        }
        return new Set[]{ completeSet, deltaSet };
    }

    /**
     * If use-deltas is set, verify the issuer and scope of the delta CRL.
     *
     * @param deltaCRL    The delta CRL.
     * @param completeCRL The complete CRL.
     * @param pkixParams  The PKIX paramaters.
     * @throws AnnotatedException if an exception occurs.
     */
    protected static void processCRLC(
        X509CRL deltaCRL,
        X509CRL completeCRL,
        PKIXExtendedParameters pkixParams)
        throws AnnotatedException
    {
        if (deltaCRL == null)
        {
            return;
        }
        IssuingDistributionPoint completeidp = null;
        try
        {
            completeidp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(
                completeCRL, Extension.issuingDistributionPoint));
        }
        catch (Exception e)
        {
            throw new AnnotatedException("issuing distribution point extension could not be decoded.", e);
        }

        if (pkixParams.isUseDeltasEnabled())
        {
            // (c) (1)
            if (!deltaCRL.getIssuerX500Principal().equals(completeCRL.getIssuerX500Principal()))
            {
                throw new AnnotatedException("complete CRL issuer does not match delta CRL issuer");
            }

            // (c) (2)
            IssuingDistributionPoint deltaidp = null;
            try
            {
                deltaidp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(
                    deltaCRL, Extension.issuingDistributionPoint));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "Issuing distribution point extension from delta CRL could not be decoded.", e);
            }

            boolean match = false;
            if (completeidp == null)
            {
                if (deltaidp == null)
                {
                    match = true;
                }
            }
            else
            {
                if (completeidp.equals(deltaidp))
                {
                    match = true;
                }
            }
            if (!match)
            {
                throw new AnnotatedException(
                    "Issuing distribution point extension from delta CRL and complete CRL does not match.");
            }

            // (c) (3)
            ASN1Primitive completeKeyIdentifier = null;
            try
            {
                completeKeyIdentifier = RevocationUtilities.getExtensionValue(
                    completeCRL, Extension.authorityKeyIdentifier);
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException(
                    "Authority key identifier extension could not be extracted from complete CRL.", e);
            }

            ASN1Primitive deltaKeyIdentifier = null;
            try
            {
                deltaKeyIdentifier = RevocationUtilities.getExtensionValue(
                    deltaCRL, Extension.authorityKeyIdentifier);
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException(
                    "Authority key identifier extension could not be extracted from delta CRL.", e);
            }

            if (completeKeyIdentifier == null)
            {
                throw new AnnotatedException("CRL authority key identifier is null.");
            }

            if (deltaKeyIdentifier == null)
            {
                throw new AnnotatedException("Delta CRL authority key identifier is null.");
            }

            if (!completeKeyIdentifier.equals(deltaKeyIdentifier))
            {
                throw new AnnotatedException(
                    "Delta CRL authority key identifier does not match complete CRL authority key identifier.");
            }
        }
    }

    protected static void processCRLI(
        Date validDate,
        X509CRL deltacrl,
        Object cert,
        CertStatus certStatus,
        PKIXExtendedParameters pkixParams)
        throws AnnotatedException
    {
        if (pkixParams.isUseDeltasEnabled() && deltacrl != null)
        {
            RevocationUtilities.getCertStatus(validDate, deltacrl, cert, certStatus);
        }
    }

    protected static void processCRLJ(
        Date validDate,
        X509CRL completecrl,
        Object cert,
        CertStatus certStatus)
        throws AnnotatedException
    {
        if (certStatus.getCertStatus() == CertStatus.UNREVOKED)
        {
            RevocationUtilities.getCertStatus(validDate, completecrl, cert, certStatus);
        }
    }

    /**
     * Checks a distribution point for revocation information for the
     * certificate <code>cert</code>.
     *
     * @param dp                 The distribution point to consider.
     * @param paramsPKIX         PKIX parameters.
     * @param cert               Certificate to check if it is revoked.
     * @param validDate          The date when the certificate revocation status should be
     *                           checked.
     * @param defaultCRLSignCert The issuer certificate of the certificate <code>cert</code>.
     * @param defaultCRLSignKey  The public key of the issuer certificate
     *                           <code>defaultCRLSignCert</code>.
     * @param certStatus         The current certificate revocation status.
     * @param reasonMask         The reasons mask which is already checked.
     * @param certPathCerts      The certificates of the certification path.
     * @throws AnnotatedException if the certificate is revoked or the status cannot be checked
     *                            or some error occurs.
     */
    static void checkCRL(
        DistributionPoint dp,
        PKIXExtendedParameters paramsPKIX,
        Date currentDate,
        Date validityDate,
        X509Certificate cert,
        X509Certificate defaultCRLSignCert,
        PublicKey defaultCRLSignKey,
        CertStatus certStatus,
        ReasonsMask reasonMask,
        List certPathCerts,
        JcaJceHelper helper)
        throws AnnotatedException, CRLNotFoundException
    {
        if (validityDate.getTime() > currentDate.getTime())
        {
            throw new AnnotatedException("Validation time is in future.");
        }

        // (a)
        /*
         * We always get timely valid CRLs, so there is no step (a) (1).
         * "locally cached" CRLs are assumed to be in getStore(), additional
         * CRLs must be enabled in the ExtendedPKIXParameters and are in
         * getAdditionalStore()
         */

        Set crls = RevocationUtilities.getCompleteCRLs(dp, cert, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
        boolean validCrlFound = false;
        AnnotatedException lastException = null;
        Iterator crl_iter = crls.iterator();

        while (crl_iter.hasNext() && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonMask.isAllReasons())
        {
            try
            {
                X509CRL crl = (X509CRL)crl_iter.next();

                // (d)
                ReasonsMask interimReasonsMask = RFC3280CertPathUtilities.processCRLD(crl, dp);

                // (e)
                /*
                 * The reasons mask is updated at the end, so only valid CRLs
                 * can update it. If this CRL does not contain new reasons it
                 * must be ignored.
                 */
                if (!interimReasonsMask.hasNewReasons(reasonMask))
                {
                    continue;
                }

                // (f)
                Set keys = RFC3280CertPathUtilities.processCRLF(crl, cert, defaultCRLSignCert, defaultCRLSignKey,
                    paramsPKIX, certPathCerts, helper);
                // (g)
                PublicKey key = RFC3280CertPathUtilities.processCRLG(crl, keys);

                X509CRL deltaCRL = null;

                if (paramsPKIX.isUseDeltasEnabled())
                {
                    // get delta CRLs
                    Set deltaCRLs = RevocationUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
                    // we only want one valid delta CRL
                    // (h)
                    deltaCRL = RFC3280CertPathUtilities.processCRLH(deltaCRLs, key);
                }

                /*
                 * CRL must be be valid at the current time, not the validation
                 * time. If a certificate is revoked with reason keyCompromise,
                 * cACompromise, it can be used for forgery, also for the past.
                 * This reason may not be contained in older CRLs.
                 */

                /*
                 * in the chain model signatures stay valid also after the
                 * certificate has been expired, so they do not have to be in
                 * the CRL validity time
                 */

                if (paramsPKIX.getValidityModel() != PKIXExtendedParameters.CHAIN_VALIDITY_MODEL)
                {
                    /*
                     * if a certificate has expired, but was revoked, it is not
                     * more in the CRL, so it would be regarded as valid if the
                     * first check is not done
                     */
                    if (cert.getNotAfter().getTime() < crl.getThisUpdate().getTime())
                    {
                        throw new AnnotatedException("No valid CRL for current time found.");
                    }
                }

                RFC3280CertPathUtilities.processCRLB1(dp, cert, crl);

                // (b) (2)
                RFC3280CertPathUtilities.processCRLB2(dp, cert, crl);

                // (c)
                RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);

                // (i)
                RFC3280CertPathUtilities.processCRLI(validityDate, deltaCRL, cert, certStatus, paramsPKIX);

                // (j)
                RFC3280CertPathUtilities.processCRLJ(validityDate, crl, cert, certStatus);

                // (k)
                if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
                {
                    certStatus.setCertStatus(CertStatus.UNREVOKED);
                }

                // update reasons mask
                reasonMask.addReasons(interimReasonsMask);

                Set criticalExtensions = crl.getCriticalExtensionOIDs();
                if (criticalExtensions != null)
                {
                    criticalExtensions = new HashSet(criticalExtensions);
                    criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
                    criticalExtensions.remove(Extension.deltaCRLIndicator.getId());

                    if (!criticalExtensions.isEmpty())
                    {
                        throw new AnnotatedException("CRL contains unsupported critical extensions.");
                    }
                }

                if (deltaCRL != null)
                {
                    criticalExtensions = deltaCRL.getCriticalExtensionOIDs();
                    if (criticalExtensions != null)
                    {
                        criticalExtensions = new HashSet(criticalExtensions);
                        criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
                        criticalExtensions.remove(Extension.deltaCRLIndicator.getId());
                        if (!criticalExtensions.isEmpty())
                        {
                            throw new AnnotatedException("Delta CRL contains unsupported critical extension.");
                        }
                    }
                }

                validCrlFound = true;
            }
            catch (AnnotatedException e)
            {
                lastException = e;
            }
        }
        if (!validCrlFound)
        {
            throw lastException;
        }
    }
}
