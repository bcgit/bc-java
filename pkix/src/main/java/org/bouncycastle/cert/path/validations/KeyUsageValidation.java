package org.bouncycastle.cert.path.validations;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.Memoable;

public class KeyUsageValidation
    implements CertPathValidation
{
    private boolean          isMandatory;

    public KeyUsageValidation()
    {
        this(true);
    }

    public KeyUsageValidation(boolean isMandatory)
    {
        this.isMandatory = isMandatory;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        context.addHandledExtension(Extension.keyUsage);

        if (!context.isEndEntity())
        {
            KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());

            if (usage != null)
            {
                if (!usage.hasUsages(KeyUsage.keyCertSign))
                {
                    throw new CertPathValidationException("Issuer certificate KeyUsage extension does not permit key signing");
                }
            }
            else
            {
                if (isMandatory)
                {
                    throw new CertPathValidationException("KeyUsage extension not present in CA certificate");
                }
            }
        }
    }

    public Memoable copy()
    {
        return new KeyUsageValidation(isMandatory);
    }

    public void reset(Memoable other)
    {
        KeyUsageValidation v = (KeyUsageValidation)other;

        this.isMandatory = v.isMandatory;
    }
}
