package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;

/**
 * Container for a list of signature subpackets.
 */
public class PGPSignatureSubpacketVector
{
    SignatureSubpacket[]    packets;
    
    PGPSignatureSubpacketVector(
        SignatureSubpacket[]    packets)
    {
        this.packets = packets;
    }
    
    public SignatureSubpacket getSubpacket(
        int    type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                return packets[i];
            }
        }
        
        return null;
    }

    /**
     * Return true if a particular subpacket type exists.
     *
     * @param type type to look for.
     * @return true if present, false otherwise.
     */
    public boolean hasSubpacket(
        int type)
    {
        return getSubpacket(type) != null;
    }

    /**
     * Return all signature subpackets of the passed in type.
     * @param type subpacket type code
     * @return an array of zero or more matching subpackets.
     */
    public SignatureSubpacket[] getSubpackets(
        int    type)
    {
        List list = new ArrayList();

        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                list.add(packets[i]);
            }
        }

        return (SignatureSubpacket[])list.toArray(new SignatureSubpacket[]{});
    }

    public PGPSignatureList getEmbeddedSignatures()
        throws PGPException
    {
        SignatureSubpacket[] sigs = getSubpackets(SignatureSubpacketTags.EMBEDDED_SIGNATURE);
        ArrayList l = new ArrayList();

        for (int i = 0; i < sigs.length; i++)
        {
            try
            {
                l.add(new PGPSignature(SignaturePacket.fromByteArray(sigs[i].getData())));
            }
            catch (IOException e)
            {
                throw new PGPException("Unable to parse signature packet: " + e.getMessage(), e);
            }
        }

        return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
    }

    public NotationData[] getNotationDataOccurrences()
    {
        SignatureSubpacket[] notations = getSubpackets(SignatureSubpacketTags.NOTATION_DATA);
        NotationData[] vals = new NotationData[notations.length];
        for (int i = 0; i < notations.length; i++)
        {
            vals[i] = (NotationData)notations[i];
        }

        return vals;
    }

    /**
     * @deprecated use  getNotationDataOccurrences()
     */
    public NotationData[] getNotationDataOccurences()
    {
        return getNotationDataOccurrences();
    }

    public long getIssuerKeyID()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((IssuerKeyID)p).getKeyID();
    }
    
    public Date getSignatureCreationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.CREATION_TIME);
        
        if (p == null)
        {
            return null;
        }
        
        return ((SignatureCreationTime)p).getTime();
    }
    
    /**
     * Return the number of seconds a signature is valid for after its creation date. A value of zero means
     * the signature never expires.
     * 
     * @return seconds a signature is valid for.
     */
    public long getSignatureExpirationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.EXPIRE_TIME);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((SignatureExpirationTime)p).getTime();
    }
    
    /**
     * Return the number of seconds a key is valid for after its creation date. A value of zero means
     * the key never expires.
     * 
     * @return seconds a key is valid for.
     */
    public long getKeyExpirationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.KEY_EXPIRE_TIME);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((KeyExpirationTime)p).getTime();
    }
    
    public int[] getPreferredHashAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_HASH_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferences();
    }
    
    public int[] getPreferredSymmetricAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferences();
    }
    
    public int[] getPreferredCompressionAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_COMP_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferences();
    }
    
    public int getKeyFlags()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.KEY_FLAGS);
        
        if (p == null)
        {
            return 0;
        }
                    
        return ((KeyFlags)p).getFlags();
    }
    
    public String getSignerUserID()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.SIGNER_USER_ID);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((SignerUserID)p).getID();
    }

    public boolean isPrimaryUserID()
    {
        PrimaryUserID primaryId = (PrimaryUserID)this.getSubpacket(SignatureSubpacketTags.PRIMARY_USER_ID);

        if (primaryId != null)
        {
            return primaryId.isPrimaryUserID();
        }

        return false;
    }

    public int[] getCriticalTags()
    {
        int    count = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].isCritical())
            {
                count++;
            }
        }
        
        int[]    list = new int[count];
        
        count = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].isCritical())
            {
                list[count++] = packets[i].getType();
            }
        }
        
        return list;
    }

    public SignatureTarget getSignatureTarget()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.SIGNATURE_TARGET);

        if (p == null)
        {
            return null;
        }

        return new SignatureTarget(p.isCritical(), p.isLongLength(), p.getData());
    }

    public Features getFeatures()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.FEATURES);

        if (p == null)
        {
            return null;
        }

        return new Features(p.isCritical(), p.isLongLength(), p.getData());
    }

    public IssuerFingerprint getIssuerFingerprint()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.ISSUER_FINGERPRINT);

        if (p == null)
        {
            return null;
        }

        return new IssuerFingerprint(p.isCritical(), p.isLongLength(), p.getData());
    }

    public IntendedRecipientFingerprint getIntendedRecipientFingerprint()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT);

        if (p == null)
        {
            return null;
        }

        return new IntendedRecipientFingerprint(p.isCritical(), p.isLongLength(), p.getData());
    }

    /**
     * Return the number of packets this vector contains.
     * 
     * @return size of the packet vector.
     */
    public int size()
    {
        return packets.length;
    }
    
    SignatureSubpacket[] toSubpacketArray()
    {
        return packets;
    }

    /**
     * Return a copy of the subpackets in this vector.
     *
     * @return an array containing the vector subpackets in order.
     */
    public SignatureSubpacket[] toArray()
    {
        SignatureSubpacket[] rv = new SignatureSubpacket[packets.length];

        System.arraycopy(packets, 0, rv, 0, rv.length);

        return rv;
    }
}
