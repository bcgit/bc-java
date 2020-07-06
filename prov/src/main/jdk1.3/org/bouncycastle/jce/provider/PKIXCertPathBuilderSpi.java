package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.PKIXCertStore;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;

/**
 * Implements the PKIX CertPathBuilding algorithm for BouncyCastle.
 * 
 * @see CertPathBuilderSpi
 */
public class PKIXCertPathBuilderSpi
    extends CertPathBuilderSpi
{
    private final boolean isForCRLCheck;

    public PKIXCertPathBuilderSpi()
    {
        this(false);
    }

    PKIXCertPathBuilderSpi(boolean isForCRLCheck)
    {
        this.isForCRLCheck = isForCRLCheck;
    }

    /**
     * Build and validate a CertPath using the given parameter.
     * 
     * @param params PKIXBuilderParameters object containing all information to
     *            build the CertPath
     */
    public CertPathBuilderResult engineBuild(CertPathParameters params)
        throws CertPathBuilderException, InvalidAlgorithmParameterException
    {
        PKIXExtendedBuilderParameters paramsPKIX;
        if (params instanceof PKIXBuilderParameters)
        {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXBuilderParameters)params);
            PKIXExtendedBuilderParameters.Builder paramsBldrPKIXBldr;

            if (params instanceof ExtendedPKIXParameters)
            {
                ExtendedPKIXBuilderParameters extPKIX = (ExtendedPKIXBuilderParameters)params;

                for (Iterator it = extPKIX.getAdditionalStores().iterator(); it.hasNext();)
                {
                     paramsPKIXBldr.addCertificateStore((PKIXCertStore)it.next());
                }
                paramsBldrPKIXBldr  = new PKIXExtendedBuilderParameters.Builder(paramsPKIXBldr.build());

                paramsBldrPKIXBldr.addExcludedCerts(extPKIX.getExcludedCerts());
                paramsBldrPKIXBldr.setMaxPathLength(extPKIX.getMaxPathLength());
            }
            else
            {
                paramsBldrPKIXBldr  = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)params);
            }

            paramsPKIX = paramsBldrPKIXBldr.build();
        }
        else if (params instanceof PKIXExtendedBuilderParameters)
        {
            paramsPKIX = (PKIXExtendedBuilderParameters)params;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                "Parameters must be an instance of "
                    + PKIXBuilderParameters.class.getName() + " or "
                    + PKIXExtendedBuilderParameters.class.getName() + ".");
        }

        Collection targets;
        Iterator targetIter;
        List certPathList = new ArrayList();
        X509Certificate cert;

        // search target certificates
        targets = CertPathValidatorUtilities.findTargets(paramsPKIX);

        CertPathBuilderResult result = null;

        // check all potential target certificates
        targetIter = targets.iterator();
        while (targetIter.hasNext() && result == null)
        {
            cert = (X509Certificate) targetIter.next();
            result = build(cert, paramsPKIX, certPathList);
        }

        if (result == null && certPathException != null)
        {
            if (certPathException instanceof AnnotatedException)
            {
                throw new CertPathBuilderException(certPathException.getMessage(), ((AnnotatedException)certPathException).getCause());
            }
            throw new CertPathBuilderException(
                "Possible certificate chain could not be validated.",
                certPathException);
        }

        if (result == null && certPathException == null)
        {
            throw new CertPathBuilderException(
                "Unable to find certificate chain.");
        }

        return result;
    }

    private Exception certPathException;

    protected CertPathBuilderResult build(X509Certificate tbvCert,
        PKIXExtendedBuilderParameters pkixParams, List tbvPath)
    {
        // If tbvCert is readily present in tbvPath, it indicates having run
        // into a cycle in the
        // PKI graph.
        if (tbvPath.contains(tbvCert))
        {
            return null;
        }
        // step out, the certificate is not allowed to appear in a certification
        // chain.
        if (pkixParams.getExcludedCerts().contains(tbvCert))
        {
            return null;
        }
        // test if certificate path exceeds maximum length
        if (pkixParams.getMaxPathLength() != -1)
        {
            if (tbvPath.size() - 1 > pkixParams.getMaxPathLength())
            {
                return null;
            }
        }

        tbvPath.add(tbvCert);

        CertificateFactory cFact;
        PKIXCertPathValidatorSpi validator;
        CertPathBuilderResult builderResult = null;

        try
        {
            cFact = new CertificateFactory();
            validator = new PKIXCertPathValidatorSpi(isForCRLCheck);
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException("Exception creating support classes.");
        }

        try
        {
            // check whether the issuer of <tbvCert> is a TrustAnchor
            if (CertPathValidatorUtilities.isIssuerTrustAnchor(tbvCert, pkixParams.getBaseParameters().getTrustAnchors(),
                pkixParams.getBaseParameters().getSigProvider()))
            {
                // exception message from possibly later tried certification
                // chains
                CertPath certPath = null;
                PKIXCertPathValidatorResult result = null;
                try
                {
                    certPath = cFact.engineGenerateCertPath(tbvPath);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                        "Certification path could not be constructed from certificate list.",
                        e);
                }

                try
                {
                    result = (PKIXCertPathValidatorResult) validator.engineValidate(
                        certPath, pkixParams);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                        "Certification path could not be validated.", e);
                }

                return new PKIXCertPathBuilderResult(certPath, result
                    .getTrustAnchor(), result.getPolicyTree(), result
                    .getPublicKey());

            }
            else
            {
                List stores = new ArrayList();


                stores.addAll(pkixParams.getBaseParameters().getCertificateStores());

                // add additional X.509 stores from locations in certificate
                try
                {
                    stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(
                        tbvCert.getExtensionValue(Extension.issuerAlternativeName.getId()), pkixParams.getBaseParameters().getNamedCertificateStoreMap()));
                }
                catch (CertificateParsingException e)
                {
                    throw new AnnotatedException(
                        "No additional X.509 stores can be added from certificate locations.",
                        e);
                }
                Collection issuers = new HashSet();
                // try to get the issuer certificate from one
                // of the stores
                try
                {
                    issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, pkixParams.getBaseParameters().getCertStores(), stores));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                        "Cannot find issuer certificate for certificate in certification path.",
                        e);
                }
                if (issuers.isEmpty())
                {
                    throw new AnnotatedException(
                        "No issuer certificate for certificate in certification path found.");
                }
                Iterator it = issuers.iterator();

                while (it.hasNext() && builderResult == null)
                {
                    X509Certificate issuer = (X509Certificate) it.next();
                    builderResult = build(issuer, pkixParams, tbvPath);
                }
            }
        }
        catch (AnnotatedException e)
        {
            certPathException = e;
        }
        if (builderResult == null)
        {
            tbvPath.remove(tbvCert);
        }
        return builderResult;
    }

}
