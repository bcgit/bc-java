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
import java.security.cert.PKIXCertPathChecker;
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
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Properties;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;

/**
 * Implements the PKIX CertPathBuilding algorithm for BouncyCastle.
 * 
 * @see CertPathBuilderSpi
 */
public class PKIXCertPathBuilderSpi_8
    extends CertPathBuilderSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final boolean isForCRLCheck;

    private AnnotatedException certPathException;
    private int maxNodes;
    private int nodesVisited;

    public PKIXCertPathBuilderSpi_8()
    {
        this(false);
    }

    PKIXCertPathBuilderSpi_8(boolean isForCRLCheck)
    {
        this.isForCRLCheck = isForCRLCheck;
    }

    public PKIXCertPathChecker engineGetRevocationChecker()
    {
        return new ProvRevocationChecker(helper);
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

        certPathException = null;
        maxNodes = Properties.asInteger(Properties.X509_MAX_CERT_PATH_BUILD_NODES, 262144);
        nodesVisited = 0;

        try
        {
            List certPathList = new ArrayList();

            // check all potential target certificates
            Collection targets = CertPathValidatorUtilities.findTargets(paramsPKIX);
            Iterator targetIter = targets.iterator();
            while (targetIter.hasNext())
            {
                X509Certificate tbvCert = (X509Certificate)targetIter.next();

                CertPathBuilderResult result = build(tbvCert, paramsPKIX, certPathList);
                if (result != null)
                {
                    return result;
                }
            }
        }
        catch (NodeBudgetExceededException e)
        {
            throw new CertPathBuilderException(e.getMessage());
        }

        if (certPathException == null)
        {
            throw new CertPathBuilderException("Unable to find certificate chain.");
        }

        throw new CertPathBuilderException(certPathException.getMessage(), certPathException.getCause());
    }

    protected CertPathBuilderResult build(X509Certificate tbvCert,
        PKIXExtendedBuilderParameters pkixParams, List tbvPath)
    {
        // Keep the depth-first search bounded: candidate issuers are matched by subject name
        // only, so a store full of like-named certificates that never chain to a trust anchor
        // could otherwise be explored as a very large number of partial paths (see
        // Properties.X509_MAX_CERT_PATH_BUILD_NODES).
        if (++nodesVisited > maxNodes)
        {
            throw new NodeBudgetExceededException(
                "certification path build exceeded node limit set by "
                    + Properties.X509_MAX_CERT_PATH_BUILD_NODES);
        }

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

        CertificateFactory cFact;
        PKIXCertPathValidatorSpi_8 validator;
        try
        {
            cFact = new CertificateFactory();
            validator = new PKIXCertPathValidatorSpi_8(isForCRLCheck);
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException("Exception creating support classes.");
        }

        tbvPath.add(tbvCert);

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
                    result = (PKIXCertPathValidatorResult)validator.engineValidate(certPath, pkixParams);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException("Certification path could not be validated.", e);
                }

                return new PKIXCertPathBuilderResult(certPath, result.getTrustAnchor(), result.getPolicyTree(),
                    result.getPublicKey());
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
                // try to get the issuer certificate from one of the stores
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
                while (it.hasNext())
                {
                    X509Certificate issuer = (X509Certificate) it.next();

                    CertPathBuilderResult builderResult = build(issuer, pkixParams, tbvPath);
                    if (builderResult != null)
                    {
                        return builderResult;
                    }
                }
            }
        }
        catch (AnnotatedException e)
        {
            certPathException = e;
        }
        finally
        {
            // Undo the add above on every exit from this frame - including the success path (the CertPath was built
            // from a copy of tbvPath) and an unwinding NodeBudgetExceededException.
            tbvPath.remove(tbvCert);
        }
        return null;
    }

    /**
     * Unchecked so it unwinds the whole recursive build (which catches only the checked
     * AnnotatedException) back to engineBuild, where it becomes a CertPathBuilderException.
     */
    private static class NodeBudgetExceededException
        extends RuntimeException
    {
        NodeBudgetExceededException(String message)
        {
            super(message);
        }
    }
}
