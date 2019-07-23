package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CRLException;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class X509CRLObject
    extends X509CRLImpl
{
    private final Object        cacheLock = new Object();
    private X509CRLInternal     internalCRLValue;

    private volatile boolean    hashValueSet;
    private volatile int        hashValue;

    X509CRLObject(JcaJceHelper bcHelper, CertificateList c) throws CRLException
    {
        super(bcHelper, c, createSigAlgName(c), createSigAlgParams(c), isIndirectCRL(c));
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }

        if (other instanceof X509CRLObject)
        {
            X509CRLObject otherBC = (X509CRLObject)other;

            if (this.hashValueSet && otherBC.hashValueSet)
            {
                if (this.hashValue != otherBC.hashValue)
                {
                    return false;
                }
            }
            else if (null == internalCRLValue || null == otherBC.internalCRLValue)
            {
                ASN1BitString signature = c.getSignature();
                if (null != signature && !signature.equals(otherBC.c.getSignature()))
                {
                    return false;
                }
            }
        }

        return getInternalCRL().equals(other);
    }

    public int hashCode()
    {
        if (!hashValueSet)
        {
            hashValue = getInternalCRL().hashCode();
            hashValueSet = true;
        }

        return hashValue;
    }

    private X509CRLInternal getInternalCRL()
    {
        synchronized (cacheLock)
        {
            if (null != internalCRLValue)
            {
                return internalCRLValue;
            }
        }

        byte[] encoding;
        try
        {
            encoding = getEncoded();
        }
        catch (CRLException e)
        {
            encoding = null;
        }

        X509CRLInternal temp = new X509CRLInternal(bcHelper, c, sigAlgName,sigAlgParams, isIndirect, encoding);

        synchronized (cacheLock)
        {
            if (null == internalCRLValue)
            {
                internalCRLValue = temp;
            }

            return internalCRLValue;
        }
    }

    private static String createSigAlgName(CertificateList c) throws CRLException
    {
        try
        {
            return X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        }
        catch (Exception e)
        {
            throw new CRLException("CRL contents invalid: " + e);
        }
    }

    private static byte[] createSigAlgParams(CertificateList c) throws CRLException
    {
        try
        {
            ASN1Encodable parameters = c.getSignatureAlgorithm().getParameters();
            if (null == parameters)
            {
                return null;
            }

            return parameters.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }
        catch (Exception e)
        {
            throw new CRLException("CRL contents invalid: " + e);
        }
    }

    private static boolean isIndirectCRL(CertificateList c) throws CRLException
    {
        try
        {
            byte[] extOctets = getExtensionOctets(c, Extension.issuingDistributionPoint.getId());
            if (null == extOctets)
            {
                return false;
            }

            return IssuingDistributionPoint.getInstance(extOctets).isIndirectCRL();
        }
        catch (Exception e)
        {
            throw new ExtCRLException("Exception reading IssuingDistributionPoint", e);
        }
    }
}
