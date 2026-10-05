package org.bouncycastle.cert.path.validations;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Memoable;

public class BasicConstraintsValidation
    implements CertPathValidation
{

    private boolean previousCertWasCA = true;
    private Integer maxPathLength = null;
    private boolean isMandatory = true;

    public BasicConstraintsValidation()
    {
        this(true);
    }

    public BasicConstraintsValidation(boolean isMandatory)
    {
        this.isMandatory = isMandatory;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        context.addHandledExtension(Extension.basicConstraints);

        // verify that the issuing certificate is in fact a CA
        if (!previousCertWasCA)
        {
            throw new CertPathValidationException("Basic constraints violated: issuer is not a CA");
        }

        // RFC 5280 § 6.1.4 (k)
        // If this certificate is a CA, remember that for processing in the next step
        BasicConstraints bc = BasicConstraints.fromExtensions(certificate.getExtensions());
        this.previousCertWasCA = (bc != null && bc.isCA()) || (bc == null && !this.isMandatory);

        // if the certificate is not self-issued (see § 4.2.1.9 and § 6.1.4 (l) of RFC 5280),
        // it "uses up" one path length unit. The last certificate in the path is not an intermediate
        // certificate and is not counted, so the limit is checked on the certificate that exceeds it
        // rather than on the one after it, which is not counted either when it is self-issued.
        // NOTE: self-issued != self-signed. We only need to compare subject DN and issuer DN here.
        if (!context.isEndEntity() && maxPathLength != null
            && !certificate.getSubject().equals(certificate.getIssuer()))
        {
            if (maxPathLength.intValue() <= 0)
            {
                throw new CertPathValidationException("Basic constraints violated: path length exceeded");
            }
            maxPathLength = Integers.valueOf(maxPathLength.intValue() - 1);
        }

        // § 6.1.4 (m)
        // Update maxPathLength if appropriate
        if (bc != null && bc.isCA())
        {
            ASN1Integer pathLenConstraint = bc.getPathLenConstraintInteger();
            if (pathLenConstraint != null)
            {
                int newPathLength = pathLenConstraint.intPositiveValueExact();
                if (maxPathLength == null || newPathLength < maxPathLength.intValue())
                {
                    maxPathLength = Integers.valueOf(newPathLength);
                }
            }
        }
    }

    public Memoable copy()
    {
        BasicConstraintsValidation result = new BasicConstraintsValidation();
        result.isMandatory = this.isMandatory;
        result.previousCertWasCA = this.previousCertWasCA;
        result.maxPathLength = this.maxPathLength;
        return result;
    }

    public void reset(Memoable other)
    {
        BasicConstraintsValidation otherBCV = (BasicConstraintsValidation)other;
        this.isMandatory = otherBCV.isMandatory;
        this.previousCertWasCA = otherBCV.previousCertWasCA;
        this.maxPathLength = otherBCV.maxPathLength;
    }
}
