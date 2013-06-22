package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.Arrays;

/**
 * general class to handle a PGP public key object.
 */
public class PGPPublicKey
    implements PublicKeyAlgorithmTags
{
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[] { PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION };
    
    PublicKeyPacket publicPk;
    TrustPacket     trustPk;
    List            keySigs = new ArrayList();
    List            ids = new ArrayList();
    List            idTrusts = new ArrayList();
    List            idSigs = new ArrayList();
    
    List            subSigs = null;

    private long    keyID;
    private byte[]  fingerprint;
    private int     keyStrength;

    private void init(KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        BCPGKey                key = publicPk.getKey();

        this.fingerprint = fingerPrintCalculator.calculateFingerprint(publicPk);

        if (publicPk.getVersion() <= 3)
        {
            RSAPublicBCPGKey    rK = (RSAPublicBCPGKey)key;
            
            this.keyID = rK.getModulus().longValue();
            this.keyStrength = rK.getModulus().bitLength();
        }
        else
        {
            this.keyID = ((long)(fingerprint[fingerprint.length - 8] & 0xff) << 56)
                            | ((long)(fingerprint[fingerprint.length - 7] & 0xff) << 48)
                            | ((long)(fingerprint[fingerprint.length - 6] & 0xff) << 40)
                            | ((long)(fingerprint[fingerprint.length - 5] & 0xff) << 32)
                            | ((long)(fingerprint[fingerprint.length - 4] & 0xff) << 24)
                            | ((long)(fingerprint[fingerprint.length - 3] & 0xff) << 16)
                            | ((long)(fingerprint[fingerprint.length - 2] & 0xff) << 8)
                            | ((fingerprint[fingerprint.length - 1] & 0xff));
            
            if (key instanceof RSAPublicBCPGKey)
            {
                this.keyStrength = ((RSAPublicBCPGKey)key).getModulus().bitLength();
            }
            else if (key instanceof DSAPublicBCPGKey)
            {
                this.keyStrength = ((DSAPublicBCPGKey)key).getP().bitLength();
            }
            else if (key instanceof ElGamalPublicBCPGKey)
            {
                this.keyStrength = ((ElGamalPublicBCPGKey)key).getP().bitLength();
            }
        }
    }
    
    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * 
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubKey actual public key to associate.
     * @param time date of creation.
     * @param provider provider to use for underlying digest calculations.
     * @throws PGPException on key creation problem.
     * @throws NoSuchProviderException if the specified provider is required and cannot be found.
     * @deprecated use JcaPGPKeyConverter.getPGPPublicKey()
     */
    public PGPPublicKey(
        int            algorithm,
        PublicKey      pubKey,
        Date           time,
        String         provider) 
        throws PGPException, NoSuchProviderException
    {
        this(new JcaPGPKeyConverter().setProvider(provider).getPGPPublicKey(algorithm, pubKey, time));
    }

    /**
         * @deprecated use JcaPGPKeyConverter.getPGPPublicKey()
     */
    public PGPPublicKey(
        int            algorithm,
        PublicKey      pubKey,
        Date           time)
        throws PGPException
    {
        this(new JcaPGPKeyConverter().getPGPPublicKey(algorithm, pubKey, time));
    }

    /**
     * Create a PGP public key from a packet descriptor using the passed in fingerPrintCalculator to do calculate
     * the fingerprint and keyID.
     *
     * @param publicKeyPacket  packet describing the public key.
     * @param fingerPrintCalculator calculator providing the digest support ot create the key fingerprint.
     * @throws PGPException  if the packet is faulty, or the required calculations fail.
     */
    public PGPPublicKey(PublicKeyPacket publicKeyPacket, KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        this.publicPk = publicKeyPacket;
        this.ids = new ArrayList();
        this.idSigs = new ArrayList();

        init(fingerPrintCalculator);
    }

    /*
     * Constructor for a sub-key.
     */
    PGPPublicKey(
        PublicKeyPacket publicPk, 
        TrustPacket     trustPk, 
        List            sigs,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
     {
        this.publicPk = publicPk;
        this.trustPk = trustPk;
        this.subSigs = sigs;
        
        init(fingerPrintCalculator);
     }

    PGPPublicKey(
        PGPPublicKey key,
        TrustPacket trust, 
        List        subSigs)
    {
        this.publicPk = key.publicPk;
        this.trustPk = trust;
        this.subSigs = subSigs;
                
        this.fingerprint = key.fingerprint;
        this.keyID = key.keyID;
        this.keyStrength = key.keyStrength;
    }
    
    /**
     * Copy constructor.
     * @param pubKey the public key to copy.
     */
    PGPPublicKey(
        PGPPublicKey    pubKey)
     {
        this.publicPk = pubKey.publicPk;
        
        this.keySigs = new ArrayList(pubKey.keySigs);
        this.ids = new ArrayList(pubKey.ids);
        this.idTrusts = new ArrayList(pubKey.idTrusts);
        this.idSigs = new ArrayList(pubKey.idSigs.size());
        for (int i = 0; i != pubKey.idSigs.size(); i++)
        {
            this.idSigs.add(new ArrayList((ArrayList)pubKey.idSigs.get(i)));
        }
       
        if (pubKey.subSigs != null)
        {
            this.subSigs = new ArrayList(pubKey.subSigs.size());
            for (int i = 0; i != pubKey.subSigs.size(); i++)
            {
                this.subSigs.add(pubKey.subSigs.get(i));
            }
        }
        
        this.fingerprint = pubKey.fingerprint;
        this.keyID = pubKey.keyID;
        this.keyStrength = pubKey.keyStrength;
     }

    PGPPublicKey(
        PublicKeyPacket publicPk,
        TrustPacket     trustPk,
        List            keySigs,
        List            ids,
        List            idTrusts,
        List            idSigs,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        this.publicPk = publicPk;
        this.trustPk = trustPk;
        this.keySigs = keySigs;
        this.ids = ids;
        this.idTrusts = idTrusts;
        this.idSigs = idSigs;
    
        init(fingerPrintCalculator);
    }
    
    /**
     * @return the version of this key.
     */
    public int getVersion()
    {
        return publicPk.getVersion();
    }
    
    /**
     * @return creation time of key.
     */
    public Date getCreationTime()
    {
        return publicPk.getTime();
    }
    
    /**
     * @return number of valid days from creation time - zero means no
     * expiry.
     */
    public int getValidDays()
    {
        if (publicPk.getVersion() > 3)
        {
            return (int)(this.getValidSeconds() / (24 * 60 * 60));
        }
        else
        {
            return publicPk.getValidDays();
        }
    }

    /**
     * Return the trust data associated with the public key, if present.
     * @return a byte array with trust data, null otherwise.
     */
    public byte[] getTrustData()
    {
        if (trustPk == null)
        {
            return null;
        }

        return Arrays.clone(trustPk.getLevelAndTrustAmount());
    }

    /**
     * @return number of valid seconds from creation time - zero means no
     * expiry.
     */
    public long getValidSeconds()
    {
        if (publicPk.getVersion() > 3)
        {
            if (this.isMasterKey())
            {
                for (int i = 0; i != MASTER_KEY_CERTIFICATION_TYPES.length; i++)
                {
                    long seconds = getExpirationTimeFromSig(true, MASTER_KEY_CERTIFICATION_TYPES[i]);
                    
                    if (seconds >= 0)
                    {
                        return seconds;
                    }
                }
            }
            else
            {
                long seconds = getExpirationTimeFromSig(false, PGPSignature.SUBKEY_BINDING);
                
                if (seconds >= 0)
                {
                    return seconds;
                }
            }
            
            return 0;
        }
        else
        {
            return (long)publicPk.getValidDays() * 24 * 60 * 60;
        }
    }

    private long getExpirationTimeFromSig(
        boolean selfSigned,
        int signatureType) 
    {
        Iterator signatures = this.getSignaturesOfType(signatureType);
        long     expiryTime = -1;

        while (signatures.hasNext())
        {
            PGPSignature sig = (PGPSignature)signatures.next();

            if (!selfSigned || sig.getKeyID() == this.getKeyID())
            {
                PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
                
                if (hashed != null)
                {
                    long current = hashed.getKeyExpirationTime();

                    if (current == 0 || current > expiryTime)
                    {
                        expiryTime = current;
                    }
                }
                else
                {
                    return 0;
                }
            }
        }
        
        return expiryTime;
    }
    
    /**
     * Return the keyID associated with the public key.
     * 
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }
    
    /**
     * Return the fingerprint of the key.
     * 
     * @return key fingerprint.
     */
    public byte[] getFingerprint()
    {
        byte[]    tmp = new byte[fingerprint.length];
        
        System.arraycopy(fingerprint, 0, tmp, 0, tmp.length);
        
        return tmp;
    }
    
    /**
     * Return true if this key has an algorithm type that makes it suitable to use for encryption.
     * <p>
     * Note: with version 4 keys KeyFlags subpackets should also be considered when present for
     * determining the preferred use of the key.
     *
     * @return true if the key algorithm is suitable for encryption.
     */
    public boolean isEncryptionKey()
    {
        int algorithm = publicPk.getAlgorithm();

        return ((algorithm == RSA_GENERAL) || (algorithm == RSA_ENCRYPT)
                || (algorithm == ELGAMAL_ENCRYPT) || (algorithm == ELGAMAL_GENERAL) || algorithm == ECDH);
    }

    /**
     * Return true if this is a master key.
     * @return true if a master key.
     */
    public boolean isMasterKey()
    {
        return (subSigs == null);
    }
    
    /**
     * Return the algorithm code associated with the public key.
     * 
     * @return int
     */
    public int getAlgorithm()
    {
        return publicPk.getAlgorithm();
    }
    
    /**
     * Return the strength of the key in bits.
     * 
     * @return bit strenght of key.
     */
    public int getBitStrength()
    {
        return keyStrength;
    }

    /**
     * Return the public key contained in the object.
     * 
     * @param provider provider to construct the key for.
     * @return a JCE/JCA public key.
     * @throws PGPException if the key algorithm is not recognised.
     * @throws NoSuchProviderException if the provider cannot be found.
     * @deprecated use a JcaPGPKeyConverter
     */
    public PublicKey getKey(
        String provider)
        throws PGPException, NoSuchProviderException
    {
        return new JcaPGPKeyConverter().setProvider(provider).getPublicKey(this);
    }

    /**
     * Return the public key contained in the object.
     *
     * @param provider provider to construct the key for.
     * @return a JCE/JCA public key.
     * @throws PGPException if the key algorithm is not recognised.
     * @deprecated use a JcaPGPKeyConverter
     */
    public PublicKey getKey(
        Provider provider)
        throws PGPException
    {
        return new JcaPGPKeyConverter().setProvider(provider).getPublicKey(this);
    }

    /**
     * Return any userIDs associated with the key.
     * 
     * @return an iterator of Strings.
     */
    public Iterator getUserIDs()
    {
        List    temp = new ArrayList();
        
        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof String)
            {
                temp.add(ids.get(i));
            }
        }
        
        return temp.iterator();
    }
    
    /**
     * Return any user attribute vectors associated with the key.
     * 
     * @return an iterator of PGPUserAttributeSubpacketVector objects.
     */
    public Iterator getUserAttributes()
    {
        List    temp = new ArrayList();
        
        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof PGPUserAttributeSubpacketVector)
            {
                temp.add(ids.get(i));
            }
        }
        
        return temp.iterator();
    }
    
    /**
     * Return any signatures associated with the passed in id.
     * 
     * @param id the id to be matched.
     * @return an iterator of PGPSignature objects.
     */
    public Iterator getSignaturesForID(
        String   id)
    {
        for (int i = 0; i != ids.size(); i++)
        {
            if (id.equals(ids.get(i)))
            {
                return ((ArrayList)idSigs.get(i)).iterator();
            }
        }
        
        return null;
    }
    
    /**
     * Return an iterator of signatures associated with the passed in user attributes.
     * 
     * @param userAttributes the vector of user attributes to be matched.
     * @return an iterator of PGPSignature objects.
     */
    public Iterator getSignaturesForUserAttribute(
        PGPUserAttributeSubpacketVector    userAttributes)
    {
        for (int i = 0; i != ids.size(); i++)
        {
            if (userAttributes.equals(ids.get(i)))
            {
                return ((ArrayList)idSigs.get(i)).iterator();
            }
        }
        
        return null;
    }
    
    /**
     * Return signatures of the passed in type that are on this key.
     * 
     * @param signatureType the type of the signature to be returned.
     * @return an iterator (possibly empty) of signatures of the given type.
     */
    public Iterator getSignaturesOfType(
        int signatureType)
    {
        List        l = new ArrayList();
        Iterator    it = this.getSignatures();
        
        while (it.hasNext())
        {
            PGPSignature    sig = (PGPSignature)it.next();
            
            if (sig.getSignatureType() == signatureType)
            {
                l.add(sig);
            }
        }
        
        return l.iterator();
    }
    
    /**
     * Return all signatures/certifications associated with this key.
     * 
     * @return an iterator (possibly empty) with all signatures/certifications.
     */
    public Iterator getSignatures()
    {
        if (subSigs == null)
        {
            List sigs = new ArrayList();

            sigs.addAll(keySigs);

            for (int i = 0; i != idSigs.size(); i++)
            {
                sigs.addAll((Collection)idSigs.get(i));
            }
            
            return sigs.iterator();
        }
        else
        {
            return subSigs.iterator();
        }
    }

    public PublicKeyPacket getPublicKeyPacket()
    {
        return publicPk;
    }

    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
        this.encode(bOut);
        
        return bOut.toByteArray();
    }
    
    public void encode(
        OutputStream    outStream) 
        throws IOException
    {
        BCPGOutputStream    out;
        
        if (outStream instanceof BCPGOutputStream)
        {
            out = (BCPGOutputStream)outStream;
        }
        else
        {
            out = new BCPGOutputStream(outStream);
        }
        
        out.writePacket(publicPk);
        if (trustPk != null)
        {
            out.writePacket(trustPk);
        }
        
        if (subSigs == null)    // not a sub-key
        {
            for (int i = 0; i != keySigs.size(); i++)
            {
                ((PGPSignature)keySigs.get(i)).encode(out);
            }
            
            for (int i = 0; i != ids.size(); i++)
            {
                if (ids.get(i) instanceof String)
                {
                    String    id = (String)ids.get(i);
                    
                    out.writePacket(new UserIDPacket(id));
                }
                else
                {
                    PGPUserAttributeSubpacketVector    v = (PGPUserAttributeSubpacketVector)ids.get(i);

                    out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
                }
                
                if (idTrusts.get(i) != null)
                {
                    out.writePacket((ContainedPacket)idTrusts.get(i));
                }
                
                List    sigs = (List)idSigs.get(i);
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((PGPSignature)sigs.get(j)).encode(out);
                }
            }
        }
        else
        {
            for (int j = 0; j != subSigs.size(); j++)
            {
                ((PGPSignature)subSigs.get(j)).encode(out);
            }
        }
    }
    
    /**
     * Check whether this (sub)key has a revocation signature on it.
     * 
     * @return boolean indicating whether this (sub)key has been revoked.
     */
    public boolean isRevoked()
    {
        int ns = 0;
        boolean revoked = false;

        if (this.isMasterKey())    // Master key
        {
            while (!revoked && (ns < keySigs.size()))
            {
                if (((PGPSignature)keySigs.get(ns++)).getSignatureType() == PGPSignature.KEY_REVOCATION)
                {
                    revoked = true;
                }
            }
        }
        else                    // Sub-key
        {
            while (!revoked && (ns < subSigs.size()))
            {
                if (((PGPSignature)subSigs.get(ns++)).getSignatureType() == PGPSignature.SUBKEY_REVOCATION)
                {
                    revoked = true;
                }
            }
        }

        return revoked;
    }


    /**
     * Add a certification for an id to the given public key.
     * 
     * @param key the key the certification is to be added to.
     * @param id the id the certification is associated with.
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey    key,
        String          id,
        PGPSignature    certification)
    {
        return addCert(key, id, certification);
    }

    /**
     * Add a certification for the given UserAttributeSubpackets to the given public key.
     *
     * @param key the key the certification is to be added to.
     * @param userAttributes the attributes the certification is associated with.
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey                    key,
        PGPUserAttributeSubpacketVector userAttributes,
        PGPSignature                    certification)
    {
        return addCert(key, userAttributes, certification);
    }

    private static PGPPublicKey addCert(
        PGPPublicKey  key,
        Object        id,
        PGPSignature  certification)
    {
        PGPPublicKey    returnKey = new PGPPublicKey(key);
        List            sigList = null;

        for (int i = 0; i != returnKey.ids.size(); i++)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                sigList = (List)returnKey.idSigs.get(i);
            }
        }

        if (sigList != null)
        {
            sigList.add(certification);
        }
        else
        {
            sigList = new ArrayList();

            sigList.add(certification);
            returnKey.ids.add(id);
            returnKey.idTrusts.add(null);
            returnKey.idSigs.add(sigList);
        }

        return returnKey;
    }

    /**
     * Remove any certifications associated with a given user attribute subpacket
     *  on a key.
     * 
     * @param key the key the certifications are to be removed from.
     * @param userAttributes the attributes to be removed.
     * @return the re-certified key, null if the user attribute subpacket was not found on the key.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey                    key,
        PGPUserAttributeSubpacketVector userAttributes)
    {
        return removeCert(key, userAttributes);
    }

    /**
     * Remove any certifications associated with a given id on a key.
     *
     * @param key the key the certifications are to be removed from.
     * @param id the id that is to be removed.
     * @return the re-certified key, null if the id was not found on the key.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey    key,
        String          id)
    {
        return removeCert(key, id);
    }

    private static PGPPublicKey removeCert(
        PGPPublicKey    key,
        Object          id)
    {
        PGPPublicKey    returnKey = new PGPPublicKey(key);
        boolean         found = false;

        for (int i = 0; i < returnKey.ids.size(); i++)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                found = true;
                returnKey.ids.remove(i);
                returnKey.idTrusts.remove(i);
                returnKey.idSigs.remove(i);
            }
        }

        if (!found)
        {
            return null;
        }

        return returnKey;
    }

    /**
     * Remove a certification associated with a given id on a key.
     * 
     * @param key the key the certifications are to be removed from.
     * @param id the id that the certification is to be removed from.
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey    key,
        String          id,
        PGPSignature    certification)
    {
        return removeCert(key, id, certification);
    }

    /**
     * Remove a certification associated with a given user attributes on a key.
     *
     * @param key the key the certifications are to be removed from.
     * @param userAttributes the user attributes that the certification is to be removed from.
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey                     key,
        PGPUserAttributeSubpacketVector  userAttributes,
        PGPSignature                     certification)
    {
        return removeCert(key, userAttributes, certification);
    }

    private static PGPPublicKey removeCert(
        PGPPublicKey    key,
        Object          id,
        PGPSignature    certification)
    {
        PGPPublicKey    returnKey = new PGPPublicKey(key);
        boolean         found = false;

        for (int i = 0; i < returnKey.ids.size(); i++)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                found = ((List)returnKey.idSigs.get(i)).remove(certification);
            }
        }

        if (!found)
        {
            return null;
        }

        return returnKey;
    }

    /**
     * Add a revocation or some other key certification to a key.
     * 
     * @param key the key the revocation is to be added to.
     * @param certification the key signature to be added.
     * @return the new changed public key object.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey    key,
        PGPSignature    certification)
    {
        if (key.isMasterKey())
        {
            if (certification.getSignatureType() == PGPSignature.SUBKEY_REVOCATION)
            {
                throw new IllegalArgumentException("signature type incorrect for master key revocation.");
            }
        }
        else
        {
            if (certification.getSignatureType() == PGPSignature.KEY_REVOCATION)
            {
                throw new IllegalArgumentException("signature type incorrect for sub-key revocation.");
            }
        }

        PGPPublicKey    returnKey = new PGPPublicKey(key);
        
        if (returnKey.subSigs != null)
        {
            returnKey.subSigs.add(certification);
        }
        else
        {
            returnKey.keySigs.add(certification);
        }
        
        return returnKey;
    }

    /**
     * Remove a certification from the key.
     *
     * @param key the key the certifications are to be removed from.
     * @param certification the certification to be removed.
     * @return the modified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey    key,
        PGPSignature    certification)
    {
        PGPPublicKey    returnKey = new PGPPublicKey(key);
        boolean         found;

        if (returnKey.subSigs != null)
        {
            found = returnKey.subSigs.remove(certification);
        }
        else
        {
            found = returnKey.keySigs.remove(certification);
        }

        if (!found)
        {
            for (Iterator it = key.getUserIDs(); it.hasNext();)
            {
                String id = (String)it.next();
                for (Iterator sIt = key.getSignaturesForID(id); sIt.hasNext();)
                {
                    if (certification == sIt.next())
                    {
                        found = true;
                        returnKey = PGPPublicKey.removeCertification(returnKey, id, certification);
                    }
                }
            }

            if (!found)
            {
                for (Iterator it = key.getUserAttributes(); it.hasNext();)
                {
                    PGPUserAttributeSubpacketVector id = (PGPUserAttributeSubpacketVector)it.next();
                    for (Iterator sIt = key.getSignaturesForUserAttribute(id); sIt.hasNext();)
                    {
                        if (certification == sIt.next())
                        {
                            found = true;
                            returnKey = PGPPublicKey.removeCertification(returnKey, id, certification);
                        }
                    }
                }
            }
        }

        return returnKey;
    }
}
