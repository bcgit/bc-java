package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

/**
 * XMMSPrivateKey
 * <pre>
 *     XMMSPrivateKey ::= SEQUENCE {
 *         version INTEGER -- 0, or 1 if maxIndex is present
 *         keyData SEQUENCE {
 *            index         INTEGER
 *            secretKeySeed OCTET STRING
 *            secretKeyPRF  OCTET STRING
 *            publicSeed    OCTET STRING
 *            root          OCTET STRING
 *            maxIndex      [0] INTEGER OPTIONAL
 *         }
 *         bdsState CHOICE {
 *             legacyBdsState [0] OCTET STRING,
 *             binaryBdsState [1] OCTET STRING
 *         } OPTIONAL
 *             -- opaque, implementation-specific traversal state. [0] carries the
 *             -- legacy Java serialization, [1] the versioned binary BDS state.
 *    }
 * </pre>
 */
public class XMSSPrivateKey
    extends ASN1Object
{
    static final int LEGACY_BDS_STATE = 0;
    static final int BINARY_BDS_STATE = 1;

    private final int version;
    private final int index;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;
    private final int maxIndex;
    private final byte[] bdsState;
    private final int bdsStateTag;

    /**
     * Base constructor. bdsState is written in the binary [1] alternative; the legacy Java
     * serialization is accepted on parsing but is no longer generated.
     */
    public XMSSPrivateKey(int index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        this.version = 0;
        this.bdsStateTag = BINARY_BDS_STATE;
        this.index = index;
        this.secretKeySeed = Arrays.clone(secretKeySeed);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF);
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
        this.bdsState = Arrays.clone(bdsState);
        this.maxIndex = -1;
    }

    /**
     * Base constructor for a key carrying maxIndex. bdsState is written in the binary [1]
     * alternative; the legacy Java serialization is accepted on parsing but is no longer generated.
     */
    public XMSSPrivateKey(int index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState, int maxIndex)
    {
        this.version = 1;
        this.bdsStateTag = BINARY_BDS_STATE;
        this.index = index;
        this.secretKeySeed = Arrays.clone(secretKeySeed);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF);
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
        this.bdsState = Arrays.clone(bdsState);
        this.maxIndex = maxIndex;
    }

    private XMSSPrivateKey(ASN1Sequence seq)
    {
        ASN1Integer v = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (!(v.hasValue(0) || v.hasValue(1)))
        {
            throw new IllegalArgumentException("unknown version of sequence");
        }
        this.version = v.intValueExact();
        
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("key sequence wrong size");
        }

        ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(1));

        this.index = ASN1Integer.getInstance(keySeq.getObjectAt(0)).intValueExact();
        this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
        this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(2)).getOctets());
        this.publicSeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(3)).getOctets());
        this.root = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(4)).getOctets());

        if (keySeq.size() == 6)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(keySeq.getObjectAt(5));
            if (tagged.getTagNo() != 0)
            {
                throw new IllegalArgumentException("unknown tag in XMSSPrivateKey");
            }
            this.maxIndex = ASN1Integer.getInstance(tagged, false).intValueExact();
        }
        else if (keySeq.size() == 5)
        {
            this.maxIndex = -1;
        }
        else
        {
            throw new IllegalArgumentException("keySeq should be 5 or 6 in length");
        }

        if (seq.size() == 3)
        {
            ASN1TaggedObject state = ASN1TaggedObject.getInstance(seq.getObjectAt(2));
            if (state.getTagNo() != LEGACY_BDS_STATE && state.getTagNo() != BINARY_BDS_STATE)
            {
                throw new IllegalArgumentException("unknown bdsState choice in XMSSPrivateKey");
            }
            this.bdsStateTag = state.getTagNo();
            this.bdsState = Arrays.clone(DEROctetString.getInstance(state, true).getOctets());
        }
        else
        {
            this.bdsStateTag = LEGACY_BDS_STATE;
            this.bdsState = null;
        }
    }

    public static XMSSPrivateKey getInstance(Object o)
    {
        if (o instanceof XMSSPrivateKey)
        {
            return (XMSSPrivateKey)o;
        }
        else if (o != null)
        {
            return new XMSSPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getVersion()
    {
        return version;
    }

    public int getIndex()
    {
        return index;
    }

    public int getMaxIndex()
    {
        return maxIndex;
    }

    public byte[] getSecretKeySeed()
    {
        return Arrays.clone(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return Arrays.clone(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public byte[] getBdsState()
    {
        return Arrays.clone(bdsState);
    }

    /**
     * Return true if bdsState was carried in the versioned binary BDS state alternative ([1]),
     * false if it was carried in the legacy Java serialization alternative ([0]).
     */
    public boolean hasBinaryBdsState()
    {
        return bdsStateTag == BINARY_BDS_STATE;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (maxIndex >= 0)
        {
            v.add(ASN1Integer.ONE); // version 1
        }
        else
        {
            v.add(ASN1Integer.ZERO); // version 0
        }

        ASN1EncodableVector vK = new ASN1EncodableVector();

        vK.add(ASN1Integer.valueOf(index));
        vK.add(new DEROctetString(secretKeySeed));
        vK.add(new DEROctetString(secretKeyPRF));
        vK.add(new DEROctetString(publicSeed));
        vK.add(new DEROctetString(root));
        if (maxIndex >= 0)
        {
            vK.add(new DERTaggedObject(false, 0, ASN1Integer.valueOf(maxIndex)));
        }
        
        v.add(new DERSequence(vK));
        if (bdsState != null)
        {
            v.add(new DERTaggedObject(true, bdsStateTag, new DEROctetString(bdsState)));
        }

        return new DERSequence(v);
    }
}
