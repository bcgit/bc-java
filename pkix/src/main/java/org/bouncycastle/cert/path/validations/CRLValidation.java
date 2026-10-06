package org.bouncycastle.cert.path.validations;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

public class CRLValidation
    implements CertPathValidation
{
    /**
     * Tolerance between our clock and the CRL issuer's when judging whether a CRL is dated in the
     * future, 15 minutes as for OCSP responses.
     */
    private static final long MAX_CLOCK_SKEW_MS = 15 * 60 * 1000L;

    private Store crls;
    private X500Name workingIssuerName;
    private SubjectPublicKeyInfo workingPublicKey;
    private X509ContentVerifierProviderBuilder contentVerifierProvider;
    private Date validDate;

    /**
     * Base constructor for CRL based revocation checking with CRL signature verification, checking
     * CRLs are current at the time each certificate is validated.
     *
     * @param trustAnchorName the name of the trust anchor the path starts from.
     * @param trustAnchorKey the public key of the trust anchor, used to verify the first CRL.
     * @param contentVerifierProvider builder for the verifier used to check CRL signatures.
     * @param crls a Store of the CRLs to consult.
     */
    public CRLValidation(X500Name trustAnchorName, SubjectPublicKeyInfo trustAnchorKey, X509ContentVerifierProviderBuilder contentVerifierProvider, Store crls)
    {
        this(trustAnchorName, trustAnchorKey, contentVerifierProvider, crls, null);
    }

    /**
     * Constructor for CRL based revocation checking with CRL signature verification at a given time.
     * <p>
     * A CRL is current at validDate when its thisUpdate is not later than validDate (allowing 15
     * minutes for clock skew) and its nextUpdate, if it states one, is not earlier. Each certificate
     * needs a current CRL from its issuer; a revocation listed on any CRL from its issuer that is
     * not dated in the future is honoured, current or not, as a revocation does not lapse when the
     * CRL listing it is superseded.
     * </p>
     * <p>
     * Delta CRLs and the scope set by an issuingDistributionPoint extension are not processed.
     * </p>
     *
     * @param trustAnchorName the name of the trust anchor the path starts from.
     * @param trustAnchorKey the public key of the trust anchor, used to verify the first CRL.
     * @param contentVerifierProvider builder for the verifier used to check CRL signatures.
     * @param crls a Store of the CRLs to consult.
     * @param validDate the time to judge the CRLs current at, null for the time of validation.
     */
    public CRLValidation(X500Name trustAnchorName, SubjectPublicKeyInfo trustAnchorKey, X509ContentVerifierProviderBuilder contentVerifierProvider, Store crls, Date validDate)
    {
        this.workingIssuerName = trustAnchorName;
        this.workingPublicKey = trustAnchorKey;
        this.contentVerifierProvider = contentVerifierProvider;
        this.crls = crls;
        this.validDate = (validDate == null) ? null : new Date(validDate.getTime());
    }

    /**
     * @deprecated this constructor cannot verify CRL signatures, so a matched CRL is rejected
     * (fail-closed) rather than trusted. Use {@link #CRLValidation(X500Name, SubjectPublicKeyInfo,
     * X509ContentVerifierProviderBuilder, Store)} so CRLs are checked against the issuer's key.
     */
    public CRLValidation(X500Name trustAnchorName, Store crls)
    {
        this(trustAnchorName, null, null, crls);
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        // TODO: add handling of delta CRLs
        Collection matches = crls.getMatches(new Selector()
        {
            public boolean match(Object obj)
            {
                X509CRLHolder crl = (X509CRLHolder)obj;

                return (crl.getIssuer().equals(workingIssuerName));
            }

            public Object clone()
            {
                return this;
            }
        });

        if (matches.isEmpty())
        {
            throw new CertPathValidationException("CRL for " + workingIssuerName + " not found");
        }

        long now = (validDate == null) ? System.currentTimeMillis() : validDate.getTime();
        boolean currentFound = false;

        for (Iterator it = matches.iterator(); it.hasNext();)
        {
            X509CRLHolder crl = (X509CRLHolder)it.next();

            // A CRL must not influence revocation status until its signature has been verified
            // against the issuing CA's public key; otherwise an attacker who can inject a CRL into
            // the Store could supply a forged CRL bearing the issuer DN and suppress or fabricate
            // revocation.
            if (contentVerifierProvider == null || workingPublicKey == null)
            {
                throw new CertPathValidationException("CRL signature verification not configured for " + workingIssuerName);
            }

            try
            {
                if (!crl.isSignatureValid(contentVerifierProvider.build(workingPublicKey)))
                {
                    throw new CertPathValidationException("CRL signature invalid for " + workingIssuerName);
                }
            }
            catch (OperatorCreationException e)
            {
                throw new CertPathValidationException("unable to create CRL verifier: " + e.getMessage(), e);
            }
            catch (CertException e)
            {
                throw new CertPathValidationException("unable to validate CRL signature: " + e.getMessage(), e);
            }

            // a CRL dated ahead of us says nothing yet, about revocation or currency
            if (crl.getThisUpdate().getTime() > now + MAX_CLOCK_SKEW_MS)
            {
                continue;
            }

            // TODO: not quite right!
            if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null)
            {
                throw new CertPathValidationException("Certificate revoked");
            }

            if (crl.getNextUpdate() == null || crl.getNextUpdate().getTime() >= now)
            {
                currentFound = true;
            }
        }

        if (!currentFound)
        {
            throw new CertPathValidationException("no current CRL for " + workingIssuerName);
        }

        this.workingIssuerName = certificate.getSubject();
        this.workingPublicKey = certificate.getSubjectPublicKeyInfo();
    }

    public Memoable copy()
    {
        return new CRLValidation(workingIssuerName, workingPublicKey, contentVerifierProvider, crls, validDate);
    }

    public void reset(Memoable other)
    {
        CRLValidation v = (CRLValidation)other;

        this.workingIssuerName = v.workingIssuerName;
        this.workingPublicKey = v.workingPublicKey;
        this.contentVerifierProvider = v.contentVerifierProvider;
        this.crls = v.crls;
        this.validDate = v.validDate;
    }
}
