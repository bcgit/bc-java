package org.bouncycastle.cert.path.validations;

import java.math.BigInteger;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.BigIntegers;
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
        // it "uses up" one path length unit.
        // NOTE: self-issued != self-signed. We only need to compare subject DN and issuer DN here.
        if (maxPathLength != null && !certificate.getSubject().equals(certificate.getIssuer()))
        {
            if (maxPathLength.intValue() < 0)
            {
                throw new CertPathValidationException("Basic constraints violated: path length exceeded");
            }
            maxPathLength = Integers.valueOf(maxPathLength.intValue() - 1);
        }

        // § 6.1.4 (m)
        // Update maxPathLength if appropriate
        if (bc != null)
        {
            BigInteger bigPathLen = bc.getPathLenConstraint();
            if (bigPathLen != null)
            {
                // use intValueExact to prevent issues with weird certificates that include ridiculous path lengths
                int newPathLength = BigIntegers.intValueExact(bigPathLen);
                maxPathLength = maxPathLength == null ? Integers.valueOf(newPathLength) : Integers.valueOf(Math.min(newPathLength, maxPathLength.intValue()));
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
