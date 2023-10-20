package org.bouncycastle.pkcs;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Exceptions;

/**
 * Holding class for a PKCS#10 certification request.
 */
public class PKCS10CertificationRequest
{
    private static Attribute[] EMPTY_ARRAY = new Attribute[0];

    private final CertificationRequest certificationRequest;
    private final boolean isAltRequest;
    private final AlgorithmIdentifier altSignature;
    private final SubjectPublicKeyInfo altPublicKey;
    private final ASN1BitString altSignatureValue;

    private static CertificationRequest parseBytes(byte[] encoding)
        throws IOException
    {
        try
        {
            CertificationRequest rv = CertificationRequest.getInstance(ASN1Primitive.fromByteArray(encoding));

            if (rv == null)
            {
                throw new PKCSIOException("empty data passed to constructor");
            }

            return rv;
        }
        catch (ClassCastException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
    }

    private static ASN1Encodable getSingleValue(Attribute at)
    {
        ASN1Encodable[] attrValues = at.getAttributeValues();
        if (attrValues.length!= 1)
        {
            throw new IllegalArgumentException("single value attribute value not size of 1");
        }

        return attrValues[0];
    }

    /**
     * Create a PKCS10CertificationRequestHolder from an underlying ASN.1 structure.
     *
     * @param certificationRequest the underlying ASN.1 structure representing a request.
     */
    public PKCS10CertificationRequest(CertificationRequest certificationRequest)
    {
        if (certificationRequest == null)
        {
            throw new NullPointerException("certificationRequest cannot be null");
        }
        this.certificationRequest = certificationRequest;

        ASN1Set attributes = certificationRequest.getCertificationRequestInfo().getAttributes();

        AlgorithmIdentifier altSig = null;
        SubjectPublicKeyInfo altPub = null;
        ASN1BitString altSigValue = null;

        if (attributes != null)
        {
            for (Enumeration en = attributes.getObjects(); en.hasMoreElements();)
            {
                Attribute at = Attribute.getInstance(en.nextElement());

                if (Extension.altSignatureAlgorithm.equals(at.getAttrType()))
                {
                    altSig = AlgorithmIdentifier.getInstance(getSingleValue(at));
                }
                if (Extension.subjectAltPublicKeyInfo.equals(at.getAttrType()))
                {
                    altPub = SubjectPublicKeyInfo.getInstance(getSingleValue(at));
                }
                if (Extension.altSignatureValue.equals(at.getAttrType()))
                {
                    altSigValue = ASN1BitString.getInstance(getSingleValue(at));
                }
            }
        }

        this.isAltRequest = (altSig != null) | (altPub != null) | (altSigValue != null);
        if (isAltRequest)
        {
            if (!((altSig != null) & (altPub != null) & (altSigValue != null)))
            {
                throw new IllegalArgumentException("invalid alternate public key details found");
            }
        }

        this.altSignature = altSig;
        this.altPublicKey = altPub;
        this.altSignatureValue = altSigValue;
    }

    /**
     * Create a PKCS10CertificationRequestHolder from the passed in bytes.
     *
     * @param encoded BER/DER encoding of the CertificationRequest structure.
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public PKCS10CertificationRequest(byte[] encoded)
        throws IOException
    {
        this(parseBytes(encoded));
    }

    /**
     * Return the underlying ASN.1 structure for this request.
     *
     * @return a CertificateRequest object.
     */
    public CertificationRequest toASN1Structure()
    {
        return certificationRequest;
    }

    /**
     * Return the subject on this request.
     *
     * @return the X500Name representing the request's subject.
     */
    public X500Name getSubject()
    {
        return X500Name.getInstance(certificationRequest.getCertificationRequestInfo().getSubject());
    }

    /**
     * Return the details of the signature algorithm used to create this request.
     *
     * @return the AlgorithmIdentifier describing the signature algorithm used to create this request.
     */
    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return certificationRequest.getSignatureAlgorithm();
    }

    /**
     * Return the bytes making up the signature associated with this request.
     *
     * @return the request signature bytes.
     */
    public byte[] getSignature()
    {
        return certificationRequest.getSignature().getOctets();
    }

    /**
     * Return the SubjectPublicKeyInfo describing the public key this request is carrying.
     *
     * @return the public key ASN.1 structure contained in the request.
     */
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return certificationRequest.getCertificationRequestInfo().getSubjectPublicKeyInfo();
    }

    /**
     * Return the attributes, if any associated with this request.
     *
     * @return an array of Attribute, zero length if none present.
     */
    public Attribute[] getAttributes()
    {
        ASN1Set attrSet = certificationRequest.getCertificationRequestInfo().getAttributes();

        if (attrSet == null)
        {
            return EMPTY_ARRAY;
        }

        Attribute[] attrs = new Attribute[attrSet.size()];

        for (int i = 0; i != attrSet.size(); i++)
        {
            attrs[i] = Attribute.getInstance(attrSet.getObjectAt(i));
        }

        return attrs;
    }

    /**
     * Return an  array of attributes matching the passed in type OID.
     *
     * @param type the type of the attribute being looked for.
     * @return an array of Attribute of the requested type, zero length if none present.
     */
    public Attribute[] getAttributes(ASN1ObjectIdentifier type)
    {
        ASN1Set attrSet = certificationRequest.getCertificationRequestInfo().getAttributes();

        if (attrSet == null)
        {
            return EMPTY_ARRAY;
        }

        List list = new ArrayList();

        for (int i = 0; i != attrSet.size(); i++)
        {
            Attribute attr = Attribute.getInstance(attrSet.getObjectAt(i));
            if (attr.getAttrType().equals(type))
            {
                list.add(attr);
            }
        }

        if (list.size() == 0)
        {
            return EMPTY_ARRAY;
        }

        return (Attribute[])list.toArray(new Attribute[list.size()]);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return certificationRequest.getEncoded();
    }

    /**
     * Validate the signature on the PKCS10 certification request in this holder.
     *
     * @param verifierProvider a ContentVerifierProvider that can generate a verifier for the signature.
     * @return true if the signature is valid, false otherwise.
     * @throws PKCSException if the signature cannot be processed or is inappropriate.
     */
    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws PKCSException
    {
        CertificationRequestInfo requestInfo = certificationRequest.getCertificationRequestInfo();

        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get(certificationRequest.getSignatureAlgorithm());

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(requestInfo.getEncoded(ASN1Encoding.DER));

            sOut.close();
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(this.getSignature());
    }

    /**
     * Return true if the certification request has an alternate public key present.
     *
     * @return true if this is a dual key request, false otherwise.
     */
    public boolean hasAltPublicKey()
    {
        return isAltRequest;
    }

    /**
     * Validate the alternate signature on the PKCS10 certification request in this holder.
     *
     * @param verifierProvider a ContentVerifierProvider that can generate a verifier for the signature.
     * @return true if the alternate signature is valid, false otherwise.
     * @throws PKCSException if the signature cannot be processed or is inappropriate.
     */
    public boolean isAltSignatureValid(ContentVerifierProvider verifierProvider)
        throws PKCSException
    {
        if (!isAltRequest)
        {
            throw new IllegalStateException("no alternate public key present");
        }

        CertificationRequestInfo requestInfo = certificationRequest.getCertificationRequestInfo();
        ASN1Set attributes = requestInfo.getAttributes();
        ASN1EncodableVector atV = new ASN1EncodableVector();

        for (Enumeration en = attributes.getObjects(); en.hasMoreElements();)
        {
            Attribute at = Attribute.getInstance(en.nextElement());

            if (Extension.altSignatureValue.equals(at.getAttrType()))
            {
                continue;
            }

            atV.add(at);
        }

        requestInfo = new CertificationRequestInfo(requestInfo.getSubject(), requestInfo.getSubjectPublicKeyInfo(), new DERSet(atV));
        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get(this.altSignature);

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(requestInfo.getEncoded(ASN1Encoding.DER));

            sOut.close();
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(this.altSignatureValue.getOctets());
    }

    /**
     * Return any extensions requested in the PKCS#10 request. If none are present, the method
     * will return null.
     *
     * @return the requested extensions, null if none are requested.
     * @throws IllegalStateException if the extension request is and is somehow invalid.
     */
    public Extensions getRequestedExtensions()
    {
        Attribute[] attributes = getAttributes();
        for (int i = 0; i != attributes.length; i++)
        {
            Attribute encodable = attributes[i];
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(encodable.getAttrType()))
            {
                ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

                ASN1Set attrValues = encodable.getAttrValues();
                if (attrValues == null || attrValues.size() == 0)
                {
                    throw new IllegalStateException("pkcs_9_at_extensionRequest present but has no value");
                }

                ASN1Sequence extensionSequence = ASN1Sequence.getInstance(attrValues.getObjectAt(0));

                try
                {
                    for (Enumeration en = extensionSequence.getObjects(); en.hasMoreElements(); )
                    {
                        ASN1Sequence itemSeq = ASN1Sequence.getInstance(en.nextElement());

                        boolean critical = itemSeq.size() == 3 && ASN1Boolean.getInstance(itemSeq.getObjectAt(1)).isTrue();
                        if (itemSeq.size() == 2)
                        {
                            extensionsGenerator.addExtension(ASN1ObjectIdentifier.getInstance(itemSeq.getObjectAt(0)), false, ASN1OctetString.getInstance(itemSeq.getObjectAt(1)).getOctets());
                        }
                        else if (itemSeq.size() == 3)
                        {
                            extensionsGenerator.addExtension(ASN1ObjectIdentifier.getInstance(itemSeq.getObjectAt(0)), critical, ASN1OctetString.getInstance(itemSeq.getObjectAt(2)).getOctets());
                        }
                        else
                        {
                            throw new IllegalStateException("incorrect sequence size of Extension get " + itemSeq.size() + " expected 2 or three");
                        }
                    }
                }
                catch (IllegalArgumentException e)
                {
                    throw Exceptions.illegalStateException("asn1 processing issue: " + e.getMessage(), e);
                }

                return extensionsGenerator.generate();
            }
        }
        return null;
    }


    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof PKCS10CertificationRequest))
        {
            return false;
        }

        PKCS10CertificationRequest other = (PKCS10CertificationRequest)o;

        return this.toASN1Structure().equals(other.toASN1Structure());
    }

    public int hashCode()
    {
        return this.toASN1Structure().hashCode();
    }
}
