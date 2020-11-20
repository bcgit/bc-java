package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * The following extensions are listed in RFC 2459 as relevant to CRLs
 * <p>
 * Authority Key Identifier
 * Issuer Alternative Name
 * CRL Number
 * Delta CRL Indicator (critical)
 * Issuing Distribution Point (critical)
 */
abstract class X509CRLImpl
    extends X509CRL
{
    protected JcaJceHelper bcHelper;
    protected CertificateList c;
    protected String sigAlgName;
    protected byte[] sigAlgParams;
    protected boolean isIndirect;

    X509CRLImpl(JcaJceHelper bcHelper, CertificateList c, String sigAlgName, byte[] sigAlgParams, boolean isIndirect)
    {
        this.bcHelper = bcHelper;
        this.c = c;
        this.sigAlgName = sigAlgName;
        this.sigAlgParams = sigAlgParams;
        this.isIndirect = isIndirect;
    }

    /**
     * Will return true if any extensions are present and marked
     * as critical as we currently dont handle any extensions!
     */
    public boolean hasUnsupportedCriticalExtension()
    {
        Set extns = getCriticalExtensionOIDs();

        if (extns == null)
        {
            return false;
        }

        extns.remove(Extension.issuingDistributionPoint.getId());
        extns.remove(Extension.deltaCRLIndicator.getId());

        return !extns.isEmpty();
    }

    private Set getExtensionOIDs(boolean critical)
    {
        if (this.getVersion() == 2)
        {
            Extensions extensions = c.getTBSCertList().getExtensions();

            if (extensions != null)
            {
                Set set = new HashSet();
                Enumeration e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    Extension ext = extensions.getExtension(oid);

                    if (critical == ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public Set getCriticalExtensionOIDs()
    {
        return getExtensionOIDs(true);
    }

    public Set getNonCriticalExtensionOIDs()
    {
        return getExtensionOIDs(false);
    }

    public byte[] getExtensionValue(String oid)
    {
        ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue)
        {
            try
            {
                return extValue.getEncoded();
            }
            catch (Exception e)
            {
                throw new IllegalStateException("error parsing " + e.toString());
            }
        }
        return null;
    }

    public byte[] getEncoded()
        throws CRLException
    {
        try
        {
            return c.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CRLException(e.toString());
        }
    }

    public void verify(PublicKey key)
        throws CRLException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        doVerify(key, new SignatureCreator()
        {
            public Signature createSignature(String sigName)
                throws NoSuchAlgorithmException, NoSuchProviderException
            {
                try
                {
                    return bcHelper.createSignature(sigName);
                }
                catch (Exception e)
                {
                    return Signature.getInstance(sigName);
                }
            }
        });
    }

    public void verify(PublicKey key, final String sigProvider)
        throws CRLException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        doVerify(key, new SignatureCreator()
        {
            public Signature createSignature(String sigName)
                throws NoSuchAlgorithmException, NoSuchProviderException
            {
                if (sigProvider != null)
                {
                    return Signature.getInstance(sigName, sigProvider);
                }
                else
                {
                    return Signature.getInstance(sigName);
                }
            }
        });
    }

    public void verify(PublicKey key, final Provider sigProvider)
        throws CRLException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException
    {
        try
        {
            doVerify(key, new SignatureCreator()
            {
                public Signature createSignature(String sigName)
                    throws NoSuchAlgorithmException, NoSuchProviderException
                {
                    if (sigProvider != null)
                    {
                        return Signature.getInstance(getSigAlgName(), sigProvider);
                    }
                    else
                    {
                        return Signature.getInstance(getSigAlgName());
                    }
                }
            });
        }
        catch (NoSuchProviderException e)
        {
            // can't happen, but just in case
            throw new NoSuchAlgorithmException("provider issue: " + e.getMessage());
        }
    }

    private void doVerify(PublicKey key, SignatureCreator sigCreator)
        throws CRLException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException, NoSuchProviderException
    {
        if (!c.getSignatureAlgorithm().equals(c.getTBSCertList().getSignature()))
        {
            throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
        }

        if (key instanceof CompositePublicKey && X509SignatureUtil.isCompositeAlgorithm(c.getSignatureAlgorithm()))
        {
            List<PublicKey> pubKeys = ((CompositePublicKey)key).getPublicKeys();
            ASN1Sequence keySeq = ASN1Sequence.getInstance(c.getSignatureAlgorithm().getParameters());
            ASN1Sequence sigSeq = ASN1Sequence.getInstance(DERBitString.getInstance(c.getSignature()).getBytes());

            boolean success = false;
            for (int i = 0; i != pubKeys.size(); i++)
            {
                if (pubKeys.get(i) == null)
                {
                    continue;
                }

                AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                String sigName = X509SignatureUtil.getSignatureName(sigAlg);

                Signature signature = sigCreator.createSignature(sigName);

                SignatureException sigExc = null;

                try
                {
                    checkSignature(
                        (PublicKey)pubKeys.get(i), signature,
                        sigAlg.getParameters(),
                        DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes());
                    success = true;
                }
                catch (SignatureException e)
                {
                    sigExc = e;
                }

                if (sigExc != null)
                {
                    throw sigExc;
                }
            }

            if (!success)
            {
                throw new InvalidKeyException("no matching key found");
            }
        }
        else if (X509SignatureUtil.isCompositeAlgorithm(c.getSignatureAlgorithm()))
        {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(c.getSignatureAlgorithm().getParameters());
            ASN1Sequence sigSeq = ASN1Sequence.getInstance(DERBitString.getInstance(c.getSignature()).getBytes());

            boolean success = false;
            for (int i = 0; i != sigSeq.size(); i++)
            {
                AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                String sigName = X509SignatureUtil.getSignatureName(sigAlg);

                SignatureException sigExc = null;

                try
                {
                    Signature signature = sigCreator.createSignature(sigName);

                    checkSignature(
                        key, signature,
                        sigAlg.getParameters(),
                        DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes());

                    success = true;
                }
                catch (InvalidKeyException e)
                {
                    // ignore
                }
                catch (NoSuchAlgorithmException e)
                {
                    // ignore
                }
                catch (SignatureException e)
                {
                    sigExc = e;
                }

                if (sigExc != null)
                {
                    throw sigExc;
                }
            }

            if (!success)
            {
                throw new InvalidKeyException("no matching key found");
            }
        }
        else
        {
            Signature sig = sigCreator.createSignature(getSigAlgName());

            if (sigAlgParams == null)
            {
                checkSignature(key, sig, null, this.getSignature());
            }
            else
            {
                try
                {
                    checkSignature(key, sig, ASN1Primitive.fromByteArray(sigAlgParams), this.getSignature());
                }
                catch (IOException e)
                {
                    throw new SignatureException("cannot decode signature parameters: " + e.getMessage());
                }
            }
        }
    }

    private void checkSignature(PublicKey key, Signature sig, ASN1Encodable sigAlgParams, byte[] encSig)
        throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CRLException
    {
        if (sigAlgParams != null)
        {
            // needs to be called before initVerify().
            X509SignatureUtil.setSignatureParameters(sig, sigAlgParams);
        }

        sig.initVerify(key);

        try
        {
            OutputStream sigOut = new BufferedOutputStream(OutputStreamFactory.createStream(sig), 512);

            c.getTBSCertList().encodeTo(sigOut, ASN1Encoding.DER);

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new CRLException(e.toString());
        }

        if (!sig.verify(encSig))
        {
            throw new SignatureException("CRL does not verify with supplied public key.");
        }
    }

    public int getVersion()
    {
        return c.getVersionNumber();
    }

    public Principal getIssuerDN()
    {
        return new X509Principal(X500Name.getInstance(c.getIssuer().toASN1Primitive()));
    }

    public X500Principal getIssuerX500Principal()
    {
        try
        {
            return new X500Principal(c.getIssuer().getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Date getThisUpdate()
    {
        return c.getThisUpdate().getDate();
    }

    public Date getNextUpdate()
    {
        Time nextUpdate = c.getNextUpdate();

        return null == nextUpdate ? null : nextUpdate.getDate();
    }

    private Set loadCRLEntries()
    {
        Set entrySet = new HashSet();
        Enumeration certs = c.getRevokedCertificateEnumeration();

        X500Name previousCertificateIssuer = null; // the issuer
        while (certs.hasMoreElements())
        {
            TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)certs.nextElement();
            X509CRLEntryObject crlEntry = new X509CRLEntryObject(entry, isIndirect, previousCertificateIssuer);
            entrySet.add(crlEntry);
            if (isIndirect && entry.hasExtensions())
            {
                Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

                if (currentCaName != null)
                {
                    previousCertificateIssuer = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
                }
            }
        }

        return entrySet;
    }

    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber)
    {
        Enumeration certs = c.getRevokedCertificateEnumeration();

        X500Name previousCertificateIssuer = null; // the issuer
        while (certs.hasMoreElements())
        {
            TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)certs.nextElement();

            if (entry.getUserCertificate().hasValue(serialNumber))
            {
                return new X509CRLEntryObject(entry, isIndirect, previousCertificateIssuer);
            }

            if (isIndirect && entry.hasExtensions())
            {
                Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

                if (currentCaName != null)
                {
                    previousCertificateIssuer = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
                }
            }
        }

        return null;
    }

    public Set getRevokedCertificates()
    {
        Set entrySet = loadCRLEntries();

        if (!entrySet.isEmpty())
        {
            return Collections.unmodifiableSet(entrySet);
        }

        return null;
    }

    public byte[] getTBSCertList()
        throws CRLException
    {
        try
        {
            return c.getTBSCertList().getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CRLException(e.toString());
        }
    }

    public byte[] getSignature()
    {
        return c.getSignature().getOctets();
    }

    public String getSigAlgName()
    {
        return sigAlgName;
    }

    public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    public byte[] getSigAlgParams()
    {
        return Arrays.clone(sigAlgParams);
    }

    /**
     * Returns a string representation of this CRL.
     *
     * @return a string representation of this CRL.
     */
    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append("              Version: ").append(this.getVersion()).append(
            nl);
        buf.append("             IssuerDN: ").append(this.getIssuerDN())
            .append(nl);
        buf.append("          This update: ").append(this.getThisUpdate())
            .append(nl);
        buf.append("          Next update: ").append(this.getNextUpdate())
            .append(nl);
        buf.append("  Signature Algorithm: ").append(this.getSigAlgName())
            .append(nl);

        X509SignatureUtil.prettyPrintSignature(this.getSignature(), buf, nl);

        Extensions extensions = c.getTBSCertList().getExtensions();

        if (extensions != null)
        {
            Enumeration e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("           Extensions: ").append(nl);
            }

            while (e.hasMoreElements())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                Extension ext = extensions.getExtension(oid);

                if (ext.getExtnValue() != null)
                {
                    byte[] octs = ext.getExtnValue().getOctets();
                    ASN1InputStream dIn = new ASN1InputStream(octs);
                    buf.append("                       critical(").append(
                        ext.isCritical()).append(") ");
                    try
                    {
                        if (oid.equals(Extension.cRLNumber))
                        {
                            buf.append(
                                new CRLNumber(ASN1Integer.getInstance(
                                    dIn.readObject()).getPositiveValue()))
                                .append(nl);
                        }
                        else if (oid.equals(Extension.deltaCRLIndicator))
                        {
                            buf.append(
                                "Base CRL: "
                                    + new CRLNumber(ASN1Integer.getInstance(
                                    dIn.readObject()).getPositiveValue()))
                                .append(nl);
                        }
                        else if (oid
                            .equals(Extension.issuingDistributionPoint))
                        {
                            buf.append(
                                IssuingDistributionPoint.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid
                            .equals(Extension.cRLDistributionPoints))
                        {
                            buf.append(
                                CRLDistPoint.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid.equals(Extension.freshestCRL))
                        {
                            buf.append(
                                CRLDistPoint.getInstance(dIn.readObject())).append(nl);
                        }
                        else
                        {
                            buf.append(oid.getId());
                            buf.append(" value = ").append(
                                ASN1Dump.dumpAsString(dIn.readObject()))
                                .append(nl);
                        }
                    }
                    catch (Exception ex)
                    {
                        buf.append(oid.getId());
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }
        Set set = getRevokedCertificates();
        if (set != null)
        {
            Iterator it = set.iterator();
            while (it.hasNext())
            {
                buf.append(it.next());
                buf.append(nl);
            }
        }
        return buf.toString();
    }

    /**
     * Checks whether the given certificate is on this CRL.
     *
     * @param cert the certificate to check for.
     * @return true if the given certificate is on this CRL,
     * false otherwise.
     */
    public boolean isRevoked(Certificate cert)
    {
        if (!cert.getType().equals("X.509"))
        {
            throw new IllegalArgumentException("X.509 CRL used with non X.509 Cert");
        }

        Enumeration certs = c.getRevokedCertificateEnumeration();

        X500Name caName = c.getIssuer();

        if (certs.hasMoreElements())
        {
            BigInteger serial = ((X509Certificate)cert).getSerialNumber();

            while (certs.hasMoreElements())
            {
                TBSCertList.CRLEntry entry = TBSCertList.CRLEntry.getInstance(certs.nextElement());

                if (isIndirect && entry.hasExtensions())
                {
                    Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

                    if (currentCaName != null)
                    {
                        caName = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
                    }
                }

                if (entry.getUserCertificate().hasValue(serial))
                {
                    X500Name issuer;

                    if (cert instanceof X509Certificate)
                    {
                        issuer = X500Name.getInstance(((X509Certificate)cert).getIssuerX500Principal().getEncoded());
                    }
                    else
                    {
                        try
                        {
                            issuer = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded()).getIssuer();
                        }
                        catch (CertificateEncodingException e)
                        {
                            throw new IllegalArgumentException("Cannot process certificate: " + e.getMessage());
                        }
                    }

                    if (!caName.equals(issuer))
                    {
                        return false;
                    }

                    return true;
                }
            }
        }

        return false;
    }

    protected static byte[] getExtensionOctets(CertificateList c, String oid)
    {
        ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue)
        {
            return extValue.getOctets();
        }
        return null;
    }

    protected static ASN1OctetString getExtensionValue(CertificateList c, String oid)
    {
        Extensions exts = c.getTBSCertList().getExtensions();
        if (null != exts)
        {
            Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
            if (null != ext)
            {
                return ext.getExtnValue();
            }
        }
        return null;
    }
}

