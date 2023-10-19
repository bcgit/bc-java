package org.bouncycastle.cert.crmf;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.ContentSigner;

/**
 * Builder for high-level objects built on {@link org.bouncycastle.asn1.crmf.CertReqMsg}.
 */
public class CertificateRequestMessageBuilder
{
    private final BigInteger certReqId;

    private ExtensionsGenerator extGenerator;
    private CertTemplateBuilder templateBuilder;
    private List controls;
    private ContentSigner popSigner;
    private PKMACBuilder pkmacBuilder;
    private char[] password;
    private GeneralName sender;
    private int popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
    private POPOPrivKey popoPrivKey;
    private ASN1Null popRaVerified;
    private PKMACValue agreeMAC;
    private AttributeTypeAndValue[] regInfo;

    public CertificateRequestMessageBuilder(BigInteger certReqId)
    {
        this.certReqId = certReqId;

        this.extGenerator = new ExtensionsGenerator();
        this.templateBuilder = new CertTemplateBuilder();
        this.controls = new ArrayList();
        this.regInfo = null;
    }

    public CertificateRequestMessageBuilder setRegInfo(AttributeTypeAndValue[] regInfo)
    {
        this.regInfo = regInfo;

        return this;
    }

    public CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setIssuer(X500Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setSubject(X500Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setSerialNumber(BigInteger serialNumber)
    {
        if (serialNumber != null)
        {
            templateBuilder.setSerialNumber(new ASN1Integer(serialNumber));
        }

        return this;
    }

    public CertificateRequestMessageBuilder setSerialNumber(ASN1Integer serialNumber)
    {
        if (serialNumber != null)
        {
            templateBuilder.setSerialNumber(serialNumber);
        }

        return this;
    }

    /**
     * Request a validity period for the certificate. Either, but not both, of the date parameters may be null.
     *
     * @param notBeforeDate not before date for certificate requested.
     * @param notAfterDate  not after date for the certificate requested.
     * @return the current builder.
     */
    public CertificateRequestMessageBuilder setValidity(Date notBeforeDate, Date notAfterDate)
    {
        templateBuilder.setValidity(new OptionalValidity(createTime(notBeforeDate), createTime(notAfterDate)));

        return this;
    }

    private Time createTime(Date date)
    {
        if (date != null)
        {
            return new Time(date);
        }

        return null;
    }

    public CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean critical,
        ASN1Encodable value)
        throws CertIOException
    {
        CRMFUtil.addExtension(extGenerator, oid, critical, value);

        return this;
    }

    public CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean critical,
        byte[] value)
    {
        extGenerator.addExtension(oid, critical, value);

        return this;
    }

    public CertificateRequestMessageBuilder addControl(Control control)
    {
        controls.add(control);

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionSigningKeySigner(ContentSigner popSigner)
    {
        if (popoPrivKey != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popSigner = popSigner;

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(SubsequentMessage msg)
    {
        if (popSigner != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
        this.popoPrivKey = new POPOPrivKey(msg);

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(int type, SubsequentMessage msg)
    {
        if (popSigner != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }
        if (type != ProofOfPossession.TYPE_KEY_ENCIPHERMENT && type != ProofOfPossession.TYPE_KEY_AGREEMENT)
        {
            throw new IllegalArgumentException("type must be ProofOfPossession.TYPE_KEY_ENCIPHERMENT or ProofOfPossession.TYPE_KEY_AGREEMENT");
        }

        this.popoType = type;
        this.popoPrivKey = new POPOPrivKey(msg);

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionAgreeMAC(PKMACValue macValue)
    {
        if (popSigner != null || popRaVerified != null || popoPrivKey != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.agreeMAC = macValue;

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionRaVerified()
    {
        if (popSigner != null || popoPrivKey != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popRaVerified = DERNull.INSTANCE;

        return this;
    }

    public CertificateRequestMessageBuilder setAuthInfoPKMAC(PKMACBuilder pkmacBuilder, char[] password)
    {
        this.pkmacBuilder = pkmacBuilder;
        this.password = password;

        return this;
    }

    public CertificateRequestMessageBuilder setAuthInfoSender(X500Name sender)
    {
        return setAuthInfoSender(new GeneralName(sender));
    }

    public CertificateRequestMessageBuilder setAuthInfoSender(GeneralName sender)
    {
        this.sender = sender;

        return this;
    }

    public CertificateRequestMessage build()
        throws CRMFException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(new ASN1Integer(certReqId));

        if (!extGenerator.isEmpty())
        {
            templateBuilder.setExtensions(extGenerator.generate());
        }

        v.add(templateBuilder.build());

        if (!controls.isEmpty())
        {
            ASN1EncodableVector controlV = new ASN1EncodableVector();

            for (Iterator it = controls.iterator(); it.hasNext();)
            {
                Control control = (Control)it.next();

                controlV.add(new AttributeTypeAndValue(control.getType(), control.getValue()));
            }

            v.add(new DERSequence(controlV));
        }

        CertRequest request = CertRequest.getInstance(new DERSequence(v));

        ProofOfPossession proofOfPossession;
        if (popSigner != null)
        {
            CertTemplate template = request.getCertTemplate();

            ProofOfPossessionSigningKeyBuilder builder;
            if (template.getSubject() == null || template.getPublicKey() == null)
            {
                SubjectPublicKeyInfo pubKeyInfo = request.getCertTemplate().getPublicKey();
                builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

                if (sender != null)
                {
                    builder.setSender(sender);
                }
                else
                {
                    builder.setPublicKeyMac(pkmacBuilder, password);
                }
            }
            else
            {
                builder = new ProofOfPossessionSigningKeyBuilder(request);
            }

            proofOfPossession = new ProofOfPossession(builder.build(popSigner));
        }
        else if (popoPrivKey != null)
        {
            proofOfPossession = new ProofOfPossession(popoType, popoPrivKey);
        }
        else if (agreeMAC != null)
        {
            proofOfPossession = new ProofOfPossession(ProofOfPossession.TYPE_KEY_AGREEMENT, new POPOPrivKey(agreeMAC));
        }
        else if (popRaVerified != null)
        {
            proofOfPossession = new ProofOfPossession();
        }
        else
        {
            proofOfPossession = new ProofOfPossession();
        }

        CertReqMsg certReqMsg = new CertReqMsg(request, proofOfPossession, regInfo);

        return new CertificateRequestMessage(certReqMsg);
    }
}
