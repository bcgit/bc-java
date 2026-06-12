package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoException;

/**
 * Implementation class for a single X.509 certificate based on the JCA. An X.509 certificate is a
 * {@link SubjectPublicKeyInfo} plus X.509 metadata, so this extends the raw public key
 * {@link JcaTlsRawKeyCertificate}, sharing all of the signature/verifier handling and overriding only
 * the public-key source and the X.509-specific accessors.
 */
public class JcaTlsCertificate
    extends JcaTlsRawKeyCertificate
{
    public static JcaTlsCertificate convert(JcaTlsCrypto crypto, TlsCertificate certificate) throws IOException
    {
        if (certificate instanceof JcaTlsCertificate)
        {
            return (JcaTlsCertificate)certificate;
        }

        return new JcaTlsCertificate(crypto, certificate.getEncoded());
    }

    public static X509Certificate parseCertificate(JcaJceHelper helper, byte[] encoding)
        throws IOException
    {
        try
        {
            /*
             * NOTE: We want to restrict 'encoding' to a binary BER encoding, but
             * CertificateFactory.generateCertificate claims to require DER encoding, and also
             * supports Base64 encodings (in PEM format), which we don't support.
             *
             * Re-encoding validates as BER and produces DER.
             */
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            byte[] derEncoding = Certificate.getInstance(asn1).getEncoded(ASN1Encoding.DER);

            ByteArrayInputStream input = new ByteArrayInputStream(derEncoding);
            X509Certificate certificate = (X509Certificate)helper.createCertificateFactory("X.509")
                .generateCertificate(input);
            if (input.available() != 0)
            {
                throw new IOException("Extra data detected in stream");
            }
            return certificate;
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to decode certificate", e);
        }
    }

    protected final X509Certificate certificate;

    public JcaTlsCertificate(JcaTlsCrypto crypto, byte[] encoding)
        throws IOException
    {
        this(crypto, parseCertificate(crypto.getHelper(), encoding));
    }

    public JcaTlsCertificate(JcaTlsCrypto crypto, X509Certificate certificate)
    {
        super(crypto);

        this.certificate = certificate;
    }

    public byte[] getEncoded() throws IOException
    {
        try
        {
            // DER encoding enforced by provider - as defined by JCA for X.509 certificates.
            return certificate.getEncoded();
        }
        catch (CertificateEncodingException e)
        {
            throw new TlsCryptoException("unable to encode certificate: " + e.getMessage(), e);
        }
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException
    {
        byte[] encoding = certificate.getExtensionValue(extensionOID.getId());
        return encoding == null ? null : ((ASN1OctetString)ASN1Primitive.fromByteArray(encoding)).getOctets();
    }

    public BigInteger getSerialNumber()
    {
        return certificate.getSerialNumber();
    }

    public String getSigAlgOID()
    {
        return certificate.getSigAlgOID();
    }

    public ASN1Encodable getSigAlgParams() throws IOException
    {
        byte[] derEncoding = certificate.getSigAlgParams();
        if (null == derEncoding)
        {
            return null;
        }

        ASN1Primitive asn1 = TlsUtils.readASN1Object(derEncoding);
        // TODO[tls] Without a known ASN.1 type, this is not-quite-right
        TlsUtils.requireDEREncoding(asn1, derEncoding);
        return asn1;
    }

    public X509Certificate getX509Certificate()
    {
        return certificate;
    }

    protected PublicKey getPublicKey() throws IOException
    {
        try
        {
            return certificate.getPublicKey();
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
        }
    }

    protected SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws IOException
    {
        return SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded());
    }

    protected boolean supportsKeyUsageBit(int keyUsageBit)
    {
        boolean[] keyUsage = certificate.getKeyUsage();

        return null == keyUsage || (keyUsage.length > keyUsageBit && keyUsage[keyUsageBit]);
    }
}
