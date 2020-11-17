package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.x509.ExtendedPKIXParameters;

/**
 * CertPathValidatorSpi implementation for X.509 Certificate validation � la RFC
 * 3280.
 */
public class PKIXCertPathValidatorSpi_8
        extends CertPathValidatorSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final boolean isForCRLCheck;

    public PKIXCertPathValidatorSpi_8()
    {
        this(false);
    }

    public PKIXCertPathValidatorSpi_8(boolean isForCRLCheck)
    {
        this.isForCRLCheck = isForCRLCheck;
    }

    public PKIXCertPathChecker engineGetRevocationChecker()
    {
        return new ProvRevocationChecker(helper);
    }

    public CertPathValidatorResult engineValidate(
            CertPath certPath,
            CertPathParameters params)
            throws CertPathValidatorException,
            InvalidAlgorithmParameterException
    {
        PKIXExtendedParameters paramsPKIX;
        if (params instanceof PKIXParameters)
        {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXParameters)params);

            if (params instanceof ExtendedPKIXParameters)
            {
                ExtendedPKIXParameters extPKIX = (ExtendedPKIXParameters)params;

                paramsPKIXBldr.setUseDeltasEnabled(extPKIX.isUseDeltasEnabled());
                paramsPKIXBldr.setValidityModel(extPKIX.getValidityModel());
            }

            paramsPKIX = paramsPKIXBldr.build();
        }
        else if (params instanceof PKIXExtendedBuilderParameters)
        {
            paramsPKIX = ((PKIXExtendedBuilderParameters)params).getBaseParameters();
        }
        else if (params instanceof PKIXExtendedParameters)
        {
            paramsPKIX = (PKIXExtendedParameters)params;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName() + " instance.");
        }

        if (paramsPKIX.getTrustAnchors() == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "trustAnchors is null, this is not allowed for certification path validation.");
        }

        //
        // 6.1.1 - inputs
        //

        //
        // (a)
        //
        List certs = certPath.getCertificates();
        int n = certs.size();

        if (certs.isEmpty())
        {
            throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
        }

        //
        // (b)
        //
        final Date currentDate = new Date();
        final Date validityDate = CertPathValidatorUtilities.getValidityDate(paramsPKIX, currentDate);

        //
        // (c)
        //
        Set userInitialPolicySet = paramsPKIX.getInitialPolicies();

        //
        // (d)
        // 
        TrustAnchor trust;
        try
        {
            trust = CertPathValidatorUtilities.findTrustAnchor((X509Certificate) certs.get(certs.size() - 1),
                    paramsPKIX.getTrustAnchors(), paramsPKIX.getSigProvider());

            if (trust == null)
            {
                throw new CertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);
            }

            checkCertificate(trust.getTrustedCert());
        }
        catch (AnnotatedException e)
        {
            throw new CertPathValidatorException(e.getMessage(), e.getUnderlyingException(), certPath, certs.size() - 1);
        }

        // RFC 5280 - CRLs must originate from the same trust anchor as the target certificate.
        paramsPKIX = new PKIXExtendedParameters.Builder(paramsPKIX).setTrustAnchor(trust).build();

        PKIXCertRevocationChecker revocationChecker = null;
        List pathCheckers = new ArrayList();
        Iterator certIter = paramsPKIX.getCertPathCheckers().iterator();
        while (certIter.hasNext())
        {
            PKIXCertPathChecker checker = (PKIXCertPathChecker)certIter.next();

            checker.init(false);

            if (checker instanceof PKIXRevocationChecker)
            {
                if (revocationChecker != null)
                {
                    throw new CertPathValidatorException("only one PKIXRevocationChecker allowed");
                }
                revocationChecker = (checker instanceof PKIXCertRevocationChecker)
                    ? (PKIXCertRevocationChecker)checker : new WrappedRevocationChecker(checker);
            }
            else
            {
                pathCheckers.add(checker);
            }
        }

        if (paramsPKIX.isRevocationEnabled() && revocationChecker == null)
        {
            revocationChecker = new ProvRevocationChecker(helper);
        }

        //
        // (e), (f), (g) are part of the paramsPKIX object.
        //

        int index = 0;
        int i;
        // Certificate for each interation of the validation loop
        // Signature information for each iteration of the validation loop
        //
        // 6.1.2 - setup
        //

        //
        // (a)
        //
        List[] policyNodes = new ArrayList[n + 1];
        for (int j = 0; j < policyNodes.length; j++)
        {
            policyNodes[j] = new ArrayList();
        }

        Set policySet = new HashSet();

        policySet.add(RFC3280CertPathUtilities.ANY_POLICY);

        PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, null, new HashSet(),
                RFC3280CertPathUtilities.ANY_POLICY, false);

        policyNodes[0].add(validPolicyTree);

        //
        // (b) and (c)
        //
        PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();

        // (d)
        //
        int explicitPolicy;
        Set acceptablePolicies = new HashSet();

        if (paramsPKIX.isExplicitPolicyRequired())
        {
            explicitPolicy = 0;
        }
        else
        {
            explicitPolicy = n + 1;
        }

        //
        // (e)
        //
        int inhibitAnyPolicy;

        if (paramsPKIX.isAnyPolicyInhibited())
        {
            inhibitAnyPolicy = 0;
        }
        else
        {
            inhibitAnyPolicy = n + 1;
        }

        //
        // (f)
        //
        int policyMapping;

        if (paramsPKIX.isPolicyMappingInhibited())
        {
            policyMapping = 0;
        }
        else
        {
            policyMapping = n + 1;
        }

        //
        // (g), (h), (i), (j)
        //
        PublicKey workingPublicKey;
        X500Name workingIssuerName;

        X509Certificate sign = trust.getTrustedCert();
        try
        {
            if (sign != null)
            {
                workingIssuerName = PrincipalUtils.getSubjectPrincipal(sign);
                workingPublicKey = sign.getPublicKey();
            }
            else
            {
                workingIssuerName = PrincipalUtils.getCA(trust);
                workingPublicKey = trust.getCAPublicKey();
            }
        }
        catch (RuntimeException ex)
        {
            throw new ExtCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", ex, certPath,
                    -1);
        }

        AlgorithmIdentifier workingAlgId = null;
        try
        {
            workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
        }
        catch (CertPathValidatorException e)
        {
            throw new ExtCertPathValidatorException(
                    "Algorithm identifier of public key of trust anchor could not be read.", e, certPath, -1);
        }
        ASN1ObjectIdentifier workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
        ASN1Encodable workingPublicKeyParameters = workingAlgId.getParameters();

        //
        // (k)
        //
        int maxPathLength = n;

        //
        // 6.1.3
        //

        if (paramsPKIX.getTargetConstraints() != null
                && !paramsPKIX.getTargetConstraints().match((X509Certificate) certs.get(0)))
        {
            throw new ExtCertPathValidatorException(
                    "Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
        }

        // 
        // initialize CertPathChecker's
        //


        X509Certificate cert = null;

        for (index = certs.size() - 1; index >= 0; index--)
        {
            // try
            // {
            //
            // i as defined in the algorithm description
            //
            i = n - index;

            //
            // set certificate to be checked in this round
            // sign and workingPublicKey and workingIssuerName are set
            // at the end of the for loop and initialized the
            // first time from the TrustAnchor
            //
            cert = (X509Certificate) certs.get(index);
            boolean verificationAlreadyPerformed = (index == certs.size() - 1);

            try
            {
                checkCertificate(cert);
            }
            catch (AnnotatedException e)
            {
                throw new CertPathValidatorException(e.getMessage(), e.getUnderlyingException(), certPath, index);
            }

            //
            // 6.1.3
            //

            RFC3280CertPathUtilities.processCertA(certPath, paramsPKIX, validityDate, revocationChecker, index,
                workingPublicKey, verificationAlreadyPerformed, workingIssuerName, sign);

            RFC3280CertPathUtilities.processCertBC(certPath, index, nameConstraintValidator, isForCRLCheck);

            validPolicyTree = RFC3280CertPathUtilities.processCertD(certPath, index, acceptablePolicies,
                    validPolicyTree, policyNodes, inhibitAnyPolicy, isForCRLCheck);

            validPolicyTree = RFC3280CertPathUtilities.processCertE(certPath, index, validPolicyTree);

            RFC3280CertPathUtilities.processCertF(certPath, index, validPolicyTree, explicitPolicy);

            //
            // 6.1.4
            //
            if (i != n)
            {
                if (cert != null && cert.getVersion() == 1)
                {
                    // we've found the trust anchor at the top of the path, ignore and keep going
                    if ((i == 1) && cert.equals(trust.getTrustedCert()))
                    {
                        continue;
                    }
                    throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", null,
                            certPath, index);
                }

                RFC3280CertPathUtilities.prepareNextCertA(certPath, index);

                validPolicyTree = RFC3280CertPathUtilities.prepareCertB(certPath, index, policyNodes, validPolicyTree,
                        policyMapping);

                RFC3280CertPathUtilities.prepareNextCertG(certPath, index, nameConstraintValidator);

                // (h)
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertH1(certPath, index, explicitPolicy);
                policyMapping = RFC3280CertPathUtilities.prepareNextCertH2(certPath, index, policyMapping);
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertH3(certPath, index, inhibitAnyPolicy);

                //
                // (i)
                //
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertI1(certPath, index, explicitPolicy);
                policyMapping = RFC3280CertPathUtilities.prepareNextCertI2(certPath, index, policyMapping);

                // (j)
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertJ(certPath, index, inhibitAnyPolicy);

                // (k)
                RFC3280CertPathUtilities.prepareNextCertK(certPath, index);

                // (l)
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertL(certPath, index, maxPathLength);

                // (m)
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertM(certPath, index, maxPathLength);

                // (n)
                RFC3280CertPathUtilities.prepareNextCertN(certPath, index);

                Set criticalExtensions = cert.getCriticalExtensionOIDs();
                if (criticalExtensions != null)
                {
                    criticalExtensions = new HashSet(criticalExtensions);

                    // these extensions are handled by the algorithm
                    criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
                    criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                    criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                    criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                    criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                }
                else
                {
                    criticalExtensions = new HashSet();
                }

                // (o)
                RFC3280CertPathUtilities.prepareNextCertO(certPath, index, criticalExtensions, pathCheckers);
                
                // set signing certificate for next round
                sign = cert;

                // (c)
                workingIssuerName = PrincipalUtils.getSubjectPrincipal(sign);

                // (d)
                try
                {
                    workingPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), index, helper);
                }
                catch (CertPathValidatorException e)
                {
                    throw new CertPathValidatorException("Next working key could not be retrieved.", e, certPath, index);
                }

                workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                // (f)
                workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
                // (e)
                workingPublicKeyParameters = workingAlgId.getParameters();
            }
        }

        //
        // 6.1.5 Wrap-up procedure
        //

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertA(explicitPolicy, cert);

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertB(certPath, index + 1, explicitPolicy);

        //
        // (c) (d) and (e) are already done
        //

        //
        // (f)
        //
        Set criticalExtensions = cert.getCriticalExtensionOIDs();

        if (criticalExtensions != null)
        {
            criticalExtensions = new HashSet(criticalExtensions);
            // these extensions are handled by the algorithm
            criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
            criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
            criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
            criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
            criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
            criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
            criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
            criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
            criticalExtensions.remove(Extension.extendedKeyUsage.getId());
        }
        else
        {
            criticalExtensions = new HashSet();
        }

        RFC3280CertPathUtilities.wrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);

        PKIXPolicyNode intersection = RFC3280CertPathUtilities.wrapupCertG(certPath, paramsPKIX, userInitialPolicySet,
                index + 1, policyNodes, validPolicyTree, acceptablePolicies);

        if ((explicitPolicy > 0) || (intersection != null))
        {
            return new PKIXCertPathValidatorResult(trust, intersection, cert.getPublicKey());
        }

        throw new CertPathValidatorException("Path processing failed on policy.", null, certPath, index);
    }

    static void checkCertificate(X509Certificate cert)
        throws AnnotatedException
    {
        if (cert instanceof BCX509Certificate)
        {
            RuntimeException cause = null;
            try
            {
                if (null != ((BCX509Certificate)cert).getTBSCertificateNative())
                {
                    return;
                }
            }
            catch (RuntimeException e)
            {
                cause = e;
            }

            throw new AnnotatedException("unable to process TBSCertificate", cause);
        }

        try
        {
            TBSCertificate.getInstance(cert.getTBSCertificate());
        }
        catch (CertificateEncodingException e)
        {
            throw new AnnotatedException("unable to process TBSCertificate", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new AnnotatedException(e.getMessage());
        }
    }
}
