package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;

public class TimeStampReq
    extends ASN1Object
{
    ASN1Integer version;

    MessageImprint messageImprint;

    ASN1ObjectIdentifier tsaPolicy;

    ASN1Integer nonce;

    ASN1Boolean certReq;

    Extensions extensions;

    public static TimeStampReq getInstance(Object o)
    {
        if (o instanceof TimeStampReq)
        {
            return (TimeStampReq) o;
        }
        else if (o != null)
        {
            return new TimeStampReq(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private TimeStampReq(ASN1Sequence seq)
    {
        int nbObjects = seq.size();

        if (nbObjects < 2)
        {
            throw new IllegalArgumentException("sequence too short to be a TimeStampReq");
        }

        int seqStart = 0;

        // version
        version = ASN1Integer.getInstance(seq.getObjectAt(seqStart));

        seqStart++;

        // messageImprint
        messageImprint = MessageImprint.getInstance(seq.getObjectAt(seqStart));

        seqStart++;

        // reqPolicy, nonce, certReq (DEFAULT FALSE) and extensions [0], each optional, in that order
        int pos = seqStart;
        if (pos < nbObjects && seq.getObjectAt(pos).toASN1Primitive() instanceof ASN1ObjectIdentifier)
        {
            tsaPolicy = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(pos++));
        }
        if (pos < nbObjects && seq.getObjectAt(pos).toASN1Primitive() instanceof ASN1Integer)
        {
            nonce = ASN1Integer.getInstance(seq.getObjectAt(pos++));
        }
        if (pos < nbObjects && seq.getObjectAt(pos).toASN1Primitive() instanceof ASN1Boolean)
        {
            certReq = ASN1Boolean.getInstance(seq.getObjectAt(pos++));
        }
        if (pos < nbObjects)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                extensions = Extensions.getInstance(tag0, false);
            }
        }

        if (pos != nbObjects)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
        }
    }

    public TimeStampReq(
        MessageImprint      messageImprint,
        ASN1ObjectIdentifier tsaPolicy,
        ASN1Integer          nonce,
        ASN1Boolean          certReq,
        Extensions      extensions)
    {
        // default
        version = ASN1Integer.ONE;

        this.messageImprint = messageImprint;
        this.tsaPolicy = tsaPolicy;
        this.nonce = nonce;
        this.certReq = certReq;
        this.extensions = extensions;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public MessageImprint getMessageImprint()
    {
        return messageImprint;
    }

    public ASN1ObjectIdentifier getReqPolicy()
    {
        return tsaPolicy;
    }

    public ASN1Integer getNonce()
    {
        return nonce;
    }

    public ASN1Boolean getCertReq()
    {
        if (certReq == null)
        {
            return ASN1Boolean.FALSE;
        }
        return certReq;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * <pre>
     * TimeStampReq ::= SEQUENCE  {
     *  version                      INTEGER  { v1(1) },
     *  messageImprint               MessageImprint,
     *    --a hash algorithm OID and the hash value of the data to be
     *    --time-stamped
     *  reqPolicy             TSAPolicyId              OPTIONAL,
     *  nonce                 INTEGER                  OPTIONAL,
     *  certReq               BOOLEAN                  DEFAULT FALSE,
     *  extensions            [0] IMPLICIT Extensions  OPTIONAL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(version);
        v.add(messageImprint);

        if (tsaPolicy != null)
        {
            v.add(tsaPolicy);
        }

        if (nonce != null)
        {
            v.add(nonce);
        }

        if (certReq != null && certReq.isTrue())
        {
            v.add(certReq);
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(false, 0, extensions));
        }

        return new DERSequence(v);
    }
}
