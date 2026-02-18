package org.bouncycastle.pkcs;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


public class DeltaCertificateRequestAttributeValueBuilder 
{

    private static final ASN1ObjectIdentifier DELTA_CSR_OID = new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2");

    private final SubjectPublicKeyInfo deltaSubjectPublicKey;
    private AlgorithmIdentifier deltaSignatureAlgorithm;
    private X500Name deltaSubject;
    private Extensions deltaExtensions;

    private AlgorithmIdentifier baseSignatureAlgorithm;
    private X500Name baseSubject;
    private Extensions baseExtensions;

    public DeltaCertificateRequestAttributeValueBuilder(SubjectPublicKeyInfo deltaSubjectPublicKey) 
    {
        this.deltaSubjectPublicKey = deltaSubjectPublicKey;
    }

    public DeltaCertificateRequestAttributeValueBuilder setDeltaSignatureAlgorithm(AlgorithmIdentifier deltaSignatureAlgorithm) 
    {
        this.deltaSignatureAlgorithm = deltaSignatureAlgorithm;

        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setDeltaSubject(X500Name deltaSubject) 
    {
        this.deltaSubject = deltaSubject;

        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setDeltaExtensions(Extensions deltaExtensions) 
    {
        this.deltaExtensions = deltaExtensions;

        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setBaseCsr(PKCS10CertificationRequest baseCsr) 
    {
        this.baseSubject = baseCsr.getSubject();
        this.baseSignatureAlgorithm = baseCsr.getSignatureAlgorithm();

        Attribute[] attributes = baseCsr.getAttributes();
            for (Attribute attr : attributes) 
                {
                if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) 
                    {
                    this.baseExtensions = Extensions.getInstance(attr.getAttributeValues()[0]);
                break;
            }
        }
        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setBaseSubject(X500Name baseSubject) 
    {
        this.baseSubject = baseSubject;
        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setBaseSignatureAlgorithm(AlgorithmIdentifier baseSignatureAlgorithm) 
    {
        this.baseSignatureAlgorithm = baseSignatureAlgorithm;
        return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setBaseExtensions(Extensions baseExtensions)
    {
        this.baseExtensions = baseExtensions;
        return this;
    }

    /**
     * Builds the DeltaCertificateRequestAttributeValue based on the provided delta and base information.
     * Only the fields that differ from the base will be included in the resulting DeltaCertificateRequestAttributeValue.
     * 
     * If no base information is provided, all delta fields will be included in the resulting DeltaCertificateRequestAttributeValue.
     * @return
     */
    public DeltaCertificateRequestAttributeValue build() 
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (deltaSubject != null && (baseSubject == null || !deltaSubject.equals(baseSubject))) 
            {
            v.add(new DERTaggedObject(true, 0, deltaSubject));
        }
        v.add(deltaSubjectPublicKey);

        if (deltaSignatureAlgorithm != null && (baseSignatureAlgorithm == null || !deltaSignatureAlgorithm.equals(baseSignatureAlgorithm))) 
            {
            v.add(new DERTaggedObject(true, 2, deltaSignatureAlgorithm));
        }

        //Check if base and delta extensions exist, if no base extension add all delta extensions
        if(deltaExtensions != null && baseExtensions == null) 
            {
            v.add(new DERTaggedObject(true, 3, deltaExtensions));
        }
        //else only add the differences between base and delta extensions
        else if(deltaExtensions != null && baseExtensions != null) 
            {
            
            if(deltaExtensions.getExtension(DELTA_CSR_OID) != null) 
                {
                throw new IllegalArgumentException("Delta extensions request must not contain Delta Certificate Descriptor extension");
            }
            
            List<Extension> diffExtensions = new ArrayList<>();
            ASN1ObjectIdentifier[] deltaOids = deltaExtensions.getExtensionOIDs();
            Set<ASN1ObjectIdentifier> seenDeltaOids = new HashSet<>();
            for(ASN1ObjectIdentifier oid : deltaOids) 
                {
                seenDeltaOids.add(oid);
                Extension deltaExt = deltaExtensions.getExtension(oid);
                Extension baseExt = baseExtensions.getExtension(oid);
                
                // Only extensions present in base are allowed
                if(baseExt == null) 
                    {
                    throw new IllegalArgumentException("Extension " + oid + " in delta but not found in base extensions");
                }
                
                // Collect if criticality or value differs from base
                if(deltaExt.isCritical() != baseExt.isCritical() || 
                   !deltaExt.getExtnValue().equals(baseExt.getExtnValue())) 
                   {
                    diffExtensions.add(deltaExt);
                }
            }
            if(seenDeltaOids.size() != baseExtensions.getExtensionOIDs().length) 
                {
                throw new IllegalArgumentException("Delta extensions must contain exactly the same OIDs as base extensions");
            }
            
            // Only add extensions field if there are differences
            if(!diffExtensions.isEmpty()) 
                {
                Extension[] diffExtensionArray = new Extension[diffExtensions.size()];
                diffExtensions.toArray(diffExtensionArray);
                v.add(new DERTaggedObject(true, 1, new Extensions(diffExtensionArray)));
            }
        }

        return new DeltaCertificateRequestAttributeValue(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"),
                new DERSet(new DERSequence(v))));
    }
}
