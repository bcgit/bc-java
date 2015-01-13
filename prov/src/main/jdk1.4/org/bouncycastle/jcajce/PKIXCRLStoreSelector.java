package org.bouncycastle.jcajce;

import java.math.BigInteger;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

/**
 * This class is a Selector implementation for X.509 certificate revocation
 * lists.
 * 
 * @see org.bouncycastle.util.Selector
 */
public class PKIXCRLStoreSelector
    implements Selector
{
    public static class Builder
    {
        private final CRLSelector baseSelector;

        private boolean deltaCRLIndicator = false;
        private boolean completeCRLEnabled = false;
        private BigInteger maxBaseCRLNumber = null;
        private byte[] issuingDistributionPoint = null;
        private boolean issuingDistributionPointEnabled = false;

        public Builder(CRLSelector certSelector)
        {
            this.baseSelector = (CRLSelector)certSelector.clone();
        }


        /**
         * If set to <code>true</code> only complete CRLs are returned.
         * <p>
         * {@link #setCompleteCRLEnabled(boolean)} and
         * {@link #setDeltaCRLIndicatorEnabled(boolean)} excluded each other.
         *
         * @param completeCRLEnabled <code>true</code> if only complete CRLs
         *            should be returned.
         */
        public Builder setCompleteCRLEnabled(boolean completeCRLEnabled)
        {
            this.completeCRLEnabled = completeCRLEnabled;

            return this;
        }

        /**
         * If this is set to <code>true</code> the CRL reported contains the delta
         * CRL indicator CRL extension.
         * <p>
         * {@link #setCompleteCRLEnabled(boolean)} and
         * {@link #setDeltaCRLIndicatorEnabled(boolean)} excluded each other.
         *
         * @param deltaCRLIndicator <code>true</code> if the delta CRL indicator
         *            extension must be in the CRL.
         */
        public Builder setDeltaCRLIndicatorEnabled(boolean deltaCRLIndicator)
        {
            this.deltaCRLIndicator = deltaCRLIndicator;

            return this;
        }

        /**
         * Sets the maximum base CRL number. Setting to <code>null</code> disables
         * this cheack.
         * <p>
         * This is only meaningful for delta CRLs. Complete CRLs must have a CRL
         * number which is greater or equal than the base number of the
         * corresponding CRL.
         *
         * @param maxBaseCRLNumber The maximum base CRL number to set.
         */
        public void setMaxBaseCRLNumber(BigInteger maxBaseCRLNumber)
        {
            this.maxBaseCRLNumber = maxBaseCRLNumber;
        }

        /**
         * Enables or disables the issuing distribution point check.
         *
         * @param issuingDistributionPointEnabled <code>true</code> to enable the
         *            issuing distribution point check.
         */
        public void setIssuingDistributionPointEnabled(
            boolean issuingDistributionPointEnabled)
        {
            this.issuingDistributionPointEnabled = issuingDistributionPointEnabled;
        }

        /**
         * Sets the issuing distribution point.
         * <p>
         * The issuing distribution point extension is a CRL extension which
         * identifies the scope and the distribution point of a CRL. The scope
         * contains among others information about revocation reasons contained in
         * the CRL. Delta CRLs and complete CRLs must have matching issuing
         * distribution points.
         * <p>
         * The byte array is cloned to protect against subsequent modifications.
         * <p>
         * You must also enable or disable this criteria with
         * {@link #setIssuingDistributionPointEnabled(boolean)}.
         *
         * @param issuingDistributionPoint The issuing distribution point to set.
         *            This is the DER encoded OCTET STRING extension value.
         * @see #getIssuingDistributionPoint()
         */
        public void setIssuingDistributionPoint(byte[] issuingDistributionPoint)
        {
            this.issuingDistributionPoint = Arrays.clone(issuingDistributionPoint);
        }

        public PKIXCRLStoreSelector build()
        {
            return new PKIXCRLStoreSelector(this);
        }
    }

    private final CRLSelector baseSelector;
    private final boolean deltaCRLIndicator;
    private final boolean completeCRLEnabled;
    private final BigInteger maxBaseCRLNumber;
    private final byte[] issuingDistributionPoint;
    private final boolean issuingDistributionPointEnabled;

    private PKIXCRLStoreSelector(Builder baseBuilder)
    {
        this.baseSelector = baseBuilder.baseSelector;
        this.deltaCRLIndicator = baseBuilder.deltaCRLIndicator;
        this.completeCRLEnabled = baseBuilder.completeCRLEnabled;
        this.maxBaseCRLNumber = baseBuilder.maxBaseCRLNumber;
        this.issuingDistributionPoint = baseBuilder.issuingDistributionPoint;
        this.issuingDistributionPointEnabled = baseBuilder.issuingDistributionPointEnabled;
    }


    /**
     * Returns if the issuing distribution point criteria should be applied.
     * Defaults to <code>false</code>.
     * <p>
     * You may also set the issuing distribution point criteria if not a missing
     * issuing distribution point should be assumed.
     * 
     * @return Returns if the issuing distribution point check is enabled.
     */
    public boolean isIssuingDistributionPointEnabled()
    {
        return issuingDistributionPointEnabled;
    }



    public boolean match(Object obj)
    {
        if (!(obj instanceof X509CRL))
        {
            return baseSelector.match((CRL)obj);
        }

        X509CRL crl = (X509CRL)obj;
        ASN1Integer dci = null;
        try
        {
            byte[] bytes = crl
                .getExtensionValue(Extension.deltaCRLIndicator.getId());
            if (bytes != null)
            {
                dci = ASN1Integer.getInstance(ASN1OctetString.getInstance(bytes).getOctets());
            }
        }
        catch (Exception e)
        {
            return false;
        }
        if (isDeltaCRLIndicatorEnabled())
        {
            if (dci == null)
            {
                return false;
            }
        }
        if (isCompleteCRLEnabled())
        {
            if (dci != null)
            {
                return false;
            }
        }
        if (dci != null)
        {

            if (maxBaseCRLNumber != null)
            {
                if (dci.getPositiveValue().compareTo(maxBaseCRLNumber) == 1)
                {
                    return false;
                }
            }
        }
        if (issuingDistributionPointEnabled)
        {
            byte[] idp = crl
                .getExtensionValue(Extension.issuingDistributionPoint
                    .getId());
            if (issuingDistributionPoint == null)
            {
                if (idp != null)
                {
                    return false;
                }
            }
            else
            {
                if (!Arrays.areEqual(idp, issuingDistributionPoint))
                {
                    return false;
                }
            }

        }
        return baseSelector.match((CRL)obj);
    }

    /**
     * Returns if this selector must match CRLs with the delta CRL indicator
     * extension set. Defaults to <code>false</code>.
     * 
     * @return Returns <code>true</code> if only CRLs with the delta CRL
     *         indicator extension are selected.
     */
    public boolean isDeltaCRLIndicatorEnabled()
    {
        return deltaCRLIndicator;
    }

    public Object clone()
    {
        return this;
    }

    /**
     * If <code>true</code> only complete CRLs are returned. Defaults to
     * <code>false</code>.
     * 
     * @return <code>true</code> if only complete CRLs are returned.
     */
    public boolean isCompleteCRLEnabled()
    {
        return completeCRLEnabled;
    }

    /**
     * Get the maximum base CRL number. Defaults to <code>null</code>.
     * 
     * @return Returns the maximum base CRL number.
     */
    public BigInteger getMaxBaseCRLNumber()
    {
        return maxBaseCRLNumber;
    }


    /**
     * Returns the issuing distribution point. Defaults to <code>null</code>,
     * which is a missing issuing distribution point extension.
     * <p>
     * The internal byte array is cloned before it is returned.
     * <p>
     * The criteria must be enable with Builder.setIssuingDistributionPointEnabled(boolean)}.
     * 
     * @return Returns the issuing distribution point.
     */
    public byte[] getIssuingDistributionPoint()
    {
        return Arrays.clone(issuingDistributionPoint);
    }

    public X509Certificate getCertificateChecking()
    {
        return ((X509CRLSelector)baseSelector).getCertificateChecking();
    }

    public static Collection getCRLs(final PKIXCRLStoreSelector selector, CertStore certStore)
        throws CertStoreException
    {
        return certStore.getCRLs(new CRLSelector()
        {
            public boolean match(CRL crl)
            {
                return selector.match(crl);
            }

            public Object clone()
            {
                return this;
            }
        });
    }
}
