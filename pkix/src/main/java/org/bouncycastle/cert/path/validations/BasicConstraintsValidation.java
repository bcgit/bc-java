package org.bouncycastle.cert.path.validations;

import java.math.BigInteger;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.Memoable;

public class BasicConstraintsValidation
    implements CertPathValidation
{
    private final boolean isMandatory;

    private BasicConstraints bc;
    private int              maxPathLength;

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
        if (maxPathLength < 0)
        {
            throw new CertPathValidationException("BasicConstraints path length exceeded");
        }

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

                        if (plc < maxPathLength)
                        {
                            maxPathLength = plc;
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
                    maxPathLength = certBC.getPathLenConstraint().intValue();
                }
            }
        }
        else
        {
            if (bc != null)
            {
                maxPathLength--;
            }
        }

        if (isMandatory && bc != null)
        {
            throw new CertPathValidationException("BasicConstraints not present in path");
        }
    }

    public Memoable copy()
    {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void reset(Memoable other)
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }
}
