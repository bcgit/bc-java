package org.bouncycastle.openssl;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

public class CertificateTrustBlock
{
    private ASN1Sequence uses;
    private ASN1Sequence prohibitions;
    private String alias;

    public CertificateTrustBlock(Set<ASN1ObjectIdentifier> uses)
    {
        this(null, uses, null);
    }

    public CertificateTrustBlock(String alias, Set<ASN1ObjectIdentifier> uses)
    {
        this(alias, uses, null);
    }

    public CertificateTrustBlock(String alias, Set<ASN1ObjectIdentifier> uses, Set<ASN1ObjectIdentifier> prohibitions)
    {
        this.alias = alias;
        this.uses = toSequence(uses);
        this.prohibitions = toSequence(prohibitions);
    }

    CertificateTrustBlock(byte[] encoded)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(encoded);

        for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
        {
            ASN1Encodable obj = (ASN1Encodable)en.nextElement();

            if (obj instanceof ASN1Sequence)
            {
                this.uses = ASN1Sequence.getInstance(obj);
            }
            else if (obj instanceof ASN1TaggedObject)
            {
                this.prohibitions = ASN1Sequence.getInstance((ASN1TaggedObject)obj, false);
            }
            else if (obj instanceof DERUTF8String)
            {
                this.alias = DERUTF8String.getInstance(obj).getString();
            }
        }
    }

    public String getAlias()
    {
        return alias;
    }

    public Set<ASN1ObjectIdentifier> getUses()
    {
        return toSet(uses);
    }

    public Set<ASN1ObjectIdentifier> getProhibitions()
    {
        return toSet(prohibitions);
    }

    private Set<ASN1ObjectIdentifier> toSet(ASN1Sequence seq)
    {
        if (seq != null)
        {
            Set<ASN1ObjectIdentifier> oids = new HashSet<ASN1ObjectIdentifier>(seq.size());

            for (Enumeration en = seq.getObjects(); en.hasMoreElements(); )
            {
                oids.add(ASN1ObjectIdentifier.getInstance(en.nextElement()));
            }

            return oids;
        }

        return Collections.EMPTY_SET;
    }

    private ASN1Sequence toSequence(Set<ASN1ObjectIdentifier> oids)
    {
        if (oids == null || oids.isEmpty())
        {
            return null;
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = oids.iterator(); it.hasNext();)
        {
           v.add((ASN1Encodable)it.next());
        }

        return new DERSequence(v);
    }

    ASN1Sequence toASN1Sequence()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (uses != null)
        {
           v.add(uses);
        }
        if (prohibitions != null)
        {
            v.add(new DERTaggedObject(false, 0, prohibitions));
        }
        if (alias != null)
        {
            v.add(new DERUTF8String(alias));
        }

        return new DERSequence(v);
    }
}
