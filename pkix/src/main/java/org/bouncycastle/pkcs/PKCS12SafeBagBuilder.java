package org.bouncycastle.pkcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * Builder for a {@link PKCS12SafeBag}. Each constructor selects the bag type
 * (shrouded key, key, cert, CRL or secret); bag attributes such as friendlyName or localKeyId
 * are layered on with {@link #addBagAttribute} before {@link #build()}.
 */
public class PKCS12SafeBagBuilder
{
    private ASN1ObjectIdentifier bagType;
    private ASN1Encodable        bagValue;
    private ASN1EncodableVector  bagAttrs = new ASN1EncodableVector();

    /**
     * Build a {@code pkcs8ShroudedKeyBag} by encrypting the supplied private key.
     *
     * @param privateKeyInfo the private key to wrap.
     * @param encryptor      the password-based output encryptor used to protect the key.
     */
    public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo, OutputEncryptor encryptor)
    {
        this.bagType = PKCSObjectIdentifiers.pkcs8ShroudedKeyBag;
        this.bagValue = new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo).build(encryptor).toASN1Structure();
    }

    /**
     * Build a {@code keyBag} carrying the supplied private key unencrypted.
     *
     * @param privateKeyInfo the private key payload.
     */
    public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo)
    {
        this.bagType = PKCSObjectIdentifiers.keyBag;
        this.bagValue = privateKeyInfo;
    }

    /**
     * Build a {@code certBag} holding an X.509 certificate.
     *
     * @param certificate the certificate to wrap.
     * @throws IOException if the certificate cannot be encoded.
     */
    public PKCS12SafeBagBuilder(X509CertificateHolder certificate)
        throws IOException
    {
        this(certificate.toASN1Structure());
    }

    /**
     * Build a {@code crlBag} holding an X.509 CRL.
     *
     * @param crl the CRL to wrap.
     * @throws IOException if the CRL cannot be encoded.
     */
    public PKCS12SafeBagBuilder(X509CRLHolder crl)
        throws IOException
    {
        this(crl.toASN1Structure());
    }

    /**
     * Build a {@code certBag} holding an X.509 certificate (low-level ASN.1 form).
     *
     * @param certificate the certificate to wrap.
     * @throws IOException if the certificate cannot be encoded.
     */
    public PKCS12SafeBagBuilder(Certificate certificate)
        throws IOException
    {
        this.bagType = PKCSObjectIdentifiers.certBag;
        this.bagValue = new CertBag(PKCSObjectIdentifiers.x509Certificate, new DEROctetString(certificate.getEncoded()));
    }

    /**
     * Build a {@code crlBag} holding an X.509 CRL (low-level ASN.1 form).
     *
     * @param crl the CRL to wrap.
     * @throws IOException if the CRL cannot be encoded.
     */
    public PKCS12SafeBagBuilder(CertificateList crl)
        throws IOException
    {
        this.bagType = PKCSObjectIdentifiers.crlBag;
        this.bagValue = new CertBag(PKCSObjectIdentifiers.x509Crl, new DEROctetString(crl.getEncoded()));
    }

    /**
     * Build a {@code secretBag} carrying an arbitrary secret value.
     *
     * @param secretBag the secret bag payload to wrap.
     */
    public PKCS12SafeBagBuilder(PKCS12SecretBag secretBag)
    {
        this.bagType = PKCSObjectIdentifiers.secretBag;
        this.bagValue = secretBag.toASN1Structure();
    }

    /**
     * Add a bag attribute (e.g. friendlyName or localKeyId) to the bag being built.
     *
     * @param attrType  the attribute OID.
     * @param attrValue the attribute value.
     * @return this builder.
     */
    public PKCS12SafeBagBuilder addBagAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        bagAttrs.add(new Attribute(attrType, new DERSet(attrValue)));

        return this;
    }

    /**
     * Assemble the SafeBag and return it.
     *
     * @return the resulting {@link PKCS12SafeBag}.
     */
    public PKCS12SafeBag build()
    {
        return new PKCS12SafeBag(new SafeBag(bagType, bagValue, new DERSet(bagAttrs)));
    }
}
