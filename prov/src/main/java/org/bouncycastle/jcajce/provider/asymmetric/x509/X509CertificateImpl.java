package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

abstract class X509CertificateImpl
    extends X509Certificate
    implements BCX509Certificate
{
    protected JcaJceHelper bcHelper;
    protected org.bouncycastle.asn1.x509.Certificate c;
    protected BasicConstraints basicConstraints;
    protected boolean[] keyUsage;
    protected String sigAlgName;
    protected byte[] sigAlgParams;

    X509CertificateImpl(JcaJceHelper bcHelper, org.bouncycastle.asn1.x509.Certificate c,
        BasicConstraints basicConstraints, boolean[] keyUsage, String sigAlgName, byte[] sigAlgParams)
    {
        this.bcHelper = bcHelper;
        this.c = c;
        this.basicConstraints = basicConstraints;
        this.keyUsage = keyUsage;
        this.sigAlgName = sigAlgName;
        this.sigAlgParams = sigAlgParams;
    }

    public X500Name getIssuerX500Name()
    {
        return c.getIssuer();
    }

    public TBSCertificate getTBSCertificateNative()
    {
        return c.getTBSCertificate();
    }

    public X500Name getSubjectX500Name()
    {
        return c.getSubject();
    }

    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        this.checkValidity(new Date());
    }

    public void checkValidity(
        Date    date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        if (date.getTime() > this.getNotAfter().getTime())  // for other VM compatibility
        {
            throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
        }

        if (date.getTime() < this.getNotBefore().getTime())
        {
            throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
        }
    }

    public int getVersion()
    {
        return c.getVersionNumber();
    }

    public BigInteger getSerialNumber()
    {
        return c.getSerialNumber().getValue();
    }

    public Principal getIssuerDN()
    {
        return new X509Principal(c.getIssuer());
    }

    public X500Principal getIssuerX500Principal()
    {
        try
        {
            byte[] encoding = c.getIssuer().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Principal getSubjectDN()
    {
        return new X509Principal(c.getSubject());
    }

    public X500Principal getSubjectX500Principal()
    {
        try
        {
            byte[] encoding = c.getSubject().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode subject DN");
        }
    }

    public Date getNotBefore()
    {
        return c.getStartDate().getDate();
    }

    public Date getNotAfter()
    {
        return c.getEndDate().getDate();
    }

    public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        try
        {
            return c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public byte[] getSignature()
    {
        return c.getSignature().getOctets();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certificate.
     */
    public String getSigAlgName()
    {
        return sigAlgName;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getSigAlgParams()
    {
        return Arrays.clone(sigAlgParams);
    }

    public boolean[] getIssuerUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getIssuerUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getSubjectUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getSubjectUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getKeyUsage()
    {
        return Arrays.clone(keyUsage);
    }

    public List getExtendedKeyUsage() 
        throws CertificateParsingException
    {
        byte[] extOctets = getExtensionOctets(c, "2.5.29.37");
        if (null == extOctets)
        {
            return null;
        }

        try
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extOctets));

            List list = new ArrayList();
            for (int i = 0; i != seq.size(); i++)
            {
                list.add(((ASN1ObjectIdentifier)seq.getObjectAt(i)).getId());
            }
            return Collections.unmodifiableList(list);
        }
        catch (Exception e)
        {
            throw new CertificateParsingException("error processing extended key usage extension");
        }
    }
    
    public int getBasicConstraints()
    {
        if (basicConstraints != null)
        {
            if (basicConstraints.isCA())
            {
                if (basicConstraints.getPathLenConstraint() == null)
                {
                    return Integer.MAX_VALUE;
                }
                else
                {
                    return basicConstraints.getPathLenConstraint().intValue();
                }
            }
            else
            {
                return -1;
            }
        }

        return -1;
    }

    public Collection getSubjectAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(c, Extension.subjectAlternativeName.getId());
    }

    public Collection getIssuerAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(c, Extension.issuerAlternativeName.getId());
    }

    public Set getCriticalExtensionOIDs() 
    {
        if (this.getVersion() == 3)
        {
            Set             set = new HashSet();
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
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

    public Set getNonCriticalExtensionOIDs() 
    {
        if (this.getVersion() == 3)
        {
            Set             set = new HashSet();
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    Extension       ext = extensions.getExtension(oid);

                    if (!ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public boolean hasUnsupportedCriticalExtension()
    {
        if (this.getVersion() == 3)
        {
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

                    if (oid.equals(Extension.keyUsage)
                     || oid.equals(Extension.certificatePolicies)
                     || oid.equals(Extension.policyMappings)
                     || oid.equals(Extension.inhibitAnyPolicy)
                     || oid.equals(Extension.cRLDistributionPoints)
                     || oid.equals(Extension.issuingDistributionPoint)
                     || oid.equals(Extension.deltaCRLIndicator)
                     || oid.equals(Extension.policyConstraints)
                     || oid.equals(Extension.basicConstraints)
                     || oid.equals(Extension.subjectAlternativeName)
                     || oid.equals(Extension.nameConstraints))
                    {
                        continue;
                    }

                    Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public PublicKey getPublicKey()
    {
        try
        {
            return BouncyCastleProvider.getPublicKey(c.getSubjectPublicKeyInfo());
        }
        catch (IOException e)
        {
            return null;   // should never happen...
        }
    }

    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        try
        {
            return c.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = Strings.lineSeparator();

        buf.append("  [0]         Version: ").append(this.getVersion()).append(nl);
        buf.append("         SerialNumber: ").append(this.getSerialNumber()).append(nl);
        buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
        buf.append("           Start Date: ").append(this.getNotBefore()).append(nl);
        buf.append("           Final Date: ").append(this.getNotAfter()).append(nl);
        buf.append("            SubjectDN: ").append(this.getSubjectDN()).append(nl);
        buf.append("           Public Key: ").append(this.getPublicKey()).append(nl);
        buf.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(nl);

        X509SignatureUtil.prettyPrintSignature(this.getSignature(), buf, nl);

        Extensions extensions = c.getTBSCertificate().getExtensions();

        if (extensions != null)
        {
            Enumeration     e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("       Extensions: \n");
            }

            while (e.hasMoreElements())
            {
                ASN1ObjectIdentifier     oid = (ASN1ObjectIdentifier)e.nextElement();
                Extension ext = extensions.getExtension(oid);

                if (ext.getExtnValue() != null)
                {
                    byte[]                  octs = ext.getExtnValue().getOctets();
                    ASN1InputStream         dIn = new ASN1InputStream(octs);
                    buf.append("                       critical(").append(ext.isCritical()).append(") ");
                    try
                    {
                        if (oid.equals(Extension.basicConstraints))
                        {
                            buf.append(BasicConstraints.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid.equals(Extension.keyUsage))
                        {
                            buf.append(KeyUsage.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeCertType))
                        {
                            buf.append(new NetscapeCertType(DERBitString.getInstance(dIn.readObject()))).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL))
                        {
                            buf.append(new NetscapeRevocationURL(DERIA5String.getInstance(dIn.readObject()))).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension))
                        {
                            buf.append(new VerisignCzagExtension(DERIA5String.getInstance(dIn.readObject()))).append(nl);
                        }
                        else 
                        {
                            buf.append(oid.getId());
                            buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
                            //buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    catch (Exception ex)
                    {
                        buf.append(oid.getId());
                   //     buf.append(" value = ").append(new String(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        return buf.toString();
    }

    public final void verify(
        PublicKey   key)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        doVerify(key, new SignatureCreator()
        {
            public Signature createSignature(String sigName)
                throws NoSuchAlgorithmException
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
    
    public final void verify(
        PublicKey   key,
        final String      sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
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

    public final void verify(
        PublicKey   key,
        final Provider sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException
    {
        try
        {
            doVerify(key, new SignatureCreator()
            {
                public Signature createSignature(String sigName)
                    throws NoSuchAlgorithmException
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
        catch (NoSuchProviderException e)
        {
            // can't happen, but just in case
            throw new NoSuchAlgorithmException("provider issue: " + e.getMessage());
        }
    }

    private void doVerify(
        PublicKey key,
        SignatureCreator signatureCreator)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException, NoSuchProviderException
    {
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

                Signature signature = signatureCreator.createSignature(sigName);

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
                    Signature signature = signatureCreator.createSignature(sigName);

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
            String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());

            Signature signature = signatureCreator.createSignature(sigName);

            if (key instanceof CompositePublicKey)
            {
                List<PublicKey> keys = ((CompositePublicKey)key).getPublicKeys();

                for (int i = 0; i != keys.size(); i++)
                {
                    try
                    {
                        checkSignature((PublicKey)keys.get(i), signature,
                            c.getSignatureAlgorithm().getParameters(), this.getSignature());
                        return;     // found the match!
                    }
                    catch (InvalidKeyException e)
                    {
                        // continue;
                    }
                }

                throw new InvalidKeyException("no matching signature found");
            }
            else
            {
                checkSignature(key, signature,
                    c.getSignatureAlgorithm().getParameters(), this.getSignature());
            }
        }
    }

    private void checkSignature(
        PublicKey key, 
        Signature signature,
        ASN1Encodable params,
        byte[] sigBytes)
        throws CertificateException, NoSuchAlgorithmException, 
            SignatureException, InvalidKeyException
    {
        if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature()))
        {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }

        // TODO This should go after the initVerify?
        X509SignatureUtil.setSignatureParameters(signature, params);

        signature.initVerify(key);

        try
        {
            OutputStream sigOut = new BufferedOutputStream(OutputStreamFactory.createStream(signature), 512);

            c.getTBSCertificate().encodeTo(sigOut, ASN1Encoding.DER);

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }

        if (!signature.verify(sigBytes))
        {
            throw new SignatureException("certificate does not verify with supplied key");
        }
    }

    private boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
    {
        if (!id1.getAlgorithm().equals(id2.getAlgorithm()))
        {
            return false;
        }

        if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL"))
        {
            if (id1.getParameters() == null)
            {
                if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }

            if (id2.getParameters() == null)
            {
                if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }
        }

        if (id1.getParameters() != null)
        {
            return id1.getParameters().equals(id2.getParameters());
        }

        if (id2.getParameters() != null)
        {
            return id2.getParameters().equals(id1.getParameters());
        }

        return true;
    }

    private static Collection getAlternativeNames(org.bouncycastle.asn1.x509.Certificate c, String oid)
        throws CertificateParsingException
    {
        byte[] extOctets = getExtensionOctets(c, oid);
        if (extOctets == null)
        {
            return null;
        }
        try
        {
            Collection temp = new ArrayList();
            Enumeration it = ASN1Sequence.getInstance(extOctets).getObjects();
            while (it.hasMoreElements())
            {
                GeneralName genName = GeneralName.getInstance(it.nextElement());
                List list = new ArrayList();
                list.add(Integers.valueOf(genName.getTagNo()));
                switch (genName.getTagNo())
                {
                case GeneralName.ediPartyName:
                case GeneralName.x400Address:
                case GeneralName.otherName:
                    list.add(genName.getEncoded());
                    break;
                case GeneralName.directoryName:
                    list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).toString());
                    break;
                case GeneralName.dNSName:
                case GeneralName.rfc822Name:
                case GeneralName.uniformResourceIdentifier:
                    list.add(((ASN1String)genName.getName()).getString());
                    break;
                case GeneralName.registeredID:
                    list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                    break;
                case GeneralName.iPAddress:
                    byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                    final String addr;
                    try
                    {
                        addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                    }
                    catch (UnknownHostException e)
                    {
                        continue;
                    }
                    list.add(addr);
                    break;
                default:
                    throw new IOException("Bad tag number: " + genName.getTagNo());
                }

                temp.add(Collections.unmodifiableList(list));
            }
            if (temp.size() == 0)
            {
                return null;
            }
            return Collections.unmodifiableCollection(temp);
        }
        catch (Exception e)
        {
            throw new CertificateParsingException(e.getMessage());
        }
    }

    protected static byte[] getExtensionOctets(org.bouncycastle.asn1.x509.Certificate c, String oid)
    {
        ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue)
        {
            return extValue.getOctets();
        }
        return null;
    }

    protected static ASN1OctetString getExtensionValue(org.bouncycastle.asn1.x509.Certificate c, String oid)
    {
        Extensions exts = c.getTBSCertificate().getExtensions();
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
