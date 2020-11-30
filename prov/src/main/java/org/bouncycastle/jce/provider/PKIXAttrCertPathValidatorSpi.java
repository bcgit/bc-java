package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509AttributeCertificate;

/**
 * CertPathValidatorSpi implementation for X.509 Attribute Certificates la RFC 3281.
 * 
 * @see org.bouncycastle.x509.ExtendedPKIXParameters
 */
public class PKIXAttrCertPathValidatorSpi
    extends CertPathValidatorSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    public PKIXAttrCertPathValidatorSpi()
    {
    }

    /**
     * Validates an attribute certificate with the given certificate path.
     * 
     * <p>
     * <code>params</code> must be an instance of
     * <code>ExtendedPKIXParameters</code>.
     * <p>
     * The target constraints in the <code>params</code> must be an
     * <code>X509AttributeCertStoreSelector</code> with at least the attribute
     * certificate criterion set. Obey that also target informations may be
     * necessary to correctly validate this attribute certificate.
     * <p>
     * The attribute certificate issuer must be added to the trusted attribute
     * issuers with {@link org.bouncycastle.x509.ExtendedPKIXParameters#setTrustedACIssuers(java.util.Set)}.
     * 
     * @param certPath The certificate path which belongs to the attribute
     *            certificate issuer public key certificate.
     * @param params The PKIX parameters.
     * @return A <code>PKIXCertPathValidatorResult</code> of the result of
     *         validating the <code>certPath</code>.
     * @throws java.security.InvalidAlgorithmParameterException if <code>params</code> is
     *             inappropriate for this validator.
     * @throws java.security.cert.CertPathValidatorException if the verification fails.
     */
    public CertPathValidatorResult engineValidate(CertPath certPath,
        CertPathParameters params) throws CertPathValidatorException,
        InvalidAlgorithmParameterException
    {
        if (!(params instanceof ExtendedPKIXParameters || params instanceof PKIXExtendedParameters))
        {
            throw new InvalidAlgorithmParameterException(
                "Parameters must be a "
                    + ExtendedPKIXParameters.class.getName() + " instance.");
        }
        Set attrCertCheckers = new HashSet();
        Set prohibitedACAttrbiutes = new HashSet();
        Set necessaryACAttributes = new HashSet();
        Set trustedACIssuers = new HashSet();

        PKIXExtendedParameters paramsPKIX;
        if (params instanceof PKIXParameters)
        {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXParameters)params);

            if (params instanceof ExtendedPKIXParameters)
            {
                ExtendedPKIXParameters extPKIX = (ExtendedPKIXParameters)params;

                paramsPKIXBldr.setUseDeltasEnabled(extPKIX.isUseDeltasEnabled());
                paramsPKIXBldr.setValidityModel(extPKIX.getValidityModel());
                attrCertCheckers = extPKIX.getAttrCertCheckers();
                prohibitedACAttrbiutes = extPKIX.getProhibitedACAttributes();
                necessaryACAttributes = extPKIX.getNecessaryACAttributes();
            }

            paramsPKIX = paramsPKIXBldr.build();
        }
        else
        {
            paramsPKIX = (PKIXExtendedParameters)params;
        }

        final Date currentDate = new Date();
        final Date validityDate = CertPathValidatorUtilities.getValidityDate(paramsPKIX, currentDate);

        Selector certSelect = paramsPKIX.getTargetConstraints();
        if (!(certSelect instanceof X509AttributeCertStoreSelector))
        {
            throw new InvalidAlgorithmParameterException(
                "TargetConstraints must be an instance of "
                    + X509AttributeCertStoreSelector.class.getName() + " for "
                    + this.getClass().getName() + " class.");
        }

        X509AttributeCertificate attrCert = ((X509AttributeCertStoreSelector) certSelect)
            .getAttributeCert();

        CertPath holderCertPath = RFC3281CertPathUtilities.processAttrCert1(attrCert, paramsPKIX);
        CertPathValidatorResult result = RFC3281CertPathUtilities.processAttrCert2(certPath, paramsPKIX);
        X509Certificate issuerCert = (X509Certificate) certPath
            .getCertificates().get(0);
        RFC3281CertPathUtilities.processAttrCert3(issuerCert, paramsPKIX);
        RFC3281CertPathUtilities.processAttrCert4(issuerCert, trustedACIssuers);
        RFC3281CertPathUtilities.processAttrCert5(attrCert, validityDate);
        // 6 already done in X509AttributeCertStoreSelector
        RFC3281CertPathUtilities.processAttrCert7(attrCert, certPath, holderCertPath, paramsPKIX, attrCertCheckers);
        RFC3281CertPathUtilities.additionalChecks(attrCert, prohibitedACAttrbiutes, necessaryACAttributes);

        RFC3281CertPathUtilities.checkCRLs(attrCert, paramsPKIX, currentDate, validityDate, issuerCert,
            certPath.getCertificates(), helper);
        return result;
    }
}
