package org.bouncycastle.cert.path.validations;

import java.util.Collection;
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
    private Store crls;
    private X500Name workingIssuerName;
    private SubjectPublicKeyInfo workingPublicKey;
    private X509ContentVerifierProviderBuilder contentVerifierProvider;

    /**
     * Base constructor for CRL based revocation checking with CRL signature verification.
     *
     * @param trustAnchorName the name of the trust anchor the path starts from.
     * @param trustAnchorKey the public key of the trust anchor, used to verify the first CRL.
     * @param contentVerifierProvider builder for the verifier used to check CRL signatures.
     * @param crls a Store of the CRLs to consult.
     */
    public CRLValidation(X500Name trustAnchorName, SubjectPublicKeyInfo trustAnchorKey, X509ContentVerifierProviderBuilder contentVerifierProvider, Store crls)
    {
        this.workingIssuerName = trustAnchorName;
        this.workingPublicKey = trustAnchorKey;
        this.contentVerifierProvider = contentVerifierProvider;
        this.crls = crls;
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

            // TODO: not quite right!
            if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null)
            {
                throw new CertPathValidationException("Certificate revoked");
            }
        }

        this.workingIssuerName = certificate.getSubject();
        this.workingPublicKey = certificate.getSubjectPublicKeyInfo();
    }

    public Memoable copy()
    {
        return new CRLValidation(workingIssuerName, workingPublicKey, contentVerifierProvider, crls);
    }

    public void reset(Memoable other)
    {
        CRLValidation v = (CRLValidation)other;

        this.workingIssuerName = v.workingIssuerName;
        this.workingPublicKey = v.workingPublicKey;
        this.contentVerifierProvider = v.contentVerifierProvider;
        this.crls = v.crls;
    }
}
