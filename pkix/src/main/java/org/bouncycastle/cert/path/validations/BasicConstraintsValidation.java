package org.bouncycastle.cert.path.validations;

import java.math.BigInteger;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.Memoable;

public class BasicConstraintsValidation
    implements CertPathValidation
{
    private boolean          isMandatory;
    private BasicConstraints bc;
    private int pathLengthRemaining;
    private BigInteger maxPathLength;

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
        if (maxPathLength != null && pathLengthRemaining < 0)
        {
            throw new CertPathValidationException("BasicConstraints path length exceeded");
        }

        context.addHandledExtension(Extension.basicConstraints);

        BasicConstraints certBC = BasicConstraints.fromExtensions(certificate.getExtensions());

        if (certBC != null)
        {
            if (bc != null)
            {
                if (certBC.isCA())
                {
                    BigInteger pathLengthConstraint = certBC.getPathLenConstraint();

                    if (pathLengthConstraint != null)
                    {
                        int plc = pathLengthConstraint.intValue();

                        if (plc < pathLengthRemaining)
                        {
                            pathLengthRemaining = plc;
                            bc = certBC;
                        }
                    }
                }
            }
            else
            {
                bc = certBC;
                if (certBC.isCA())
                {
                    maxPathLength = certBC.getPathLenConstraint();

                    if (maxPathLength != null)
                    {
                        pathLengthRemaining = maxPathLength.intValue();
                    }
                }
            }
        }
        else
        {
            if (bc != null)
            {
                pathLengthRemaining--;
            }
        }

        if (isMandatory && bc == null)
        {
            throw new CertPathValidationException("BasicConstraints not present in path");
        }
    }

    public Memoable copy()
    {
        BasicConstraintsValidation v = new BasicConstraintsValidation(isMandatory);

        v.bc = this.bc;
        v.pathLengthRemaining = this.pathLengthRemaining;

        return v;
    }

    public void reset(Memoable other)
    {
        BasicConstraintsValidation v = (BasicConstraintsValidation)other;

        this.isMandatory = v.isMandatory;
        this.bc = v.bc;
        this.pathLengthRemaining = v.pathLengthRemaining;
    }
}
