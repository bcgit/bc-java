package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserDataPacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Arrays;

/**
 * general class to handle a PGP public key object.
 */
public class PGPPublicKey
    implements PublicKeyAlgorithmTags
{
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION, PGPSignature.DIRECT_KEY};

    PublicKeyPacket publicPk;
    TrustPacket trustPk;
    List<PGPSignature> keySigs = new ArrayList<PGPSignature>();
    List<UserDataPacket> ids = new ArrayList<UserDataPacket>();
    List<TrustPacket> idTrusts = new ArrayList<TrustPacket>();
    List<List<PGPSignature>> idSigs = new ArrayList<List<PGPSignature>>();

    List<PGPSignature> subSigs = null;

    private long keyID;
    private byte[] fingerprint;
    private int keyStrength;

    private void init(KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();

        this.fingerprint = fingerPrintCalculator.calculateFingerprint(publicPk);

        if (publicPk.getVersion() <= PublicKeyPacket.VERSION_3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            this.keyID = rK.getModulus().longValue();
            this.keyStrength = rK.getModulus().bitLength();
        }
        else if (publicPk.getVersion() == PublicKeyPacket.VERSION_4)
        {
            this.keyID = ((long)(fingerprint[fingerprint.length - 8] & 0xff) << 56)
                | ((long)(fingerprint[fingerprint.length - 7] & 0xff) << 48)
                | ((long)(fingerprint[fingerprint.length - 6] & 0xff) << 40)
                | ((long)(fingerprint[fingerprint.length - 5] & 0xff) << 32)
                | ((long)(fingerprint[fingerprint.length - 4] & 0xff) << 24)
                | ((long)(fingerprint[fingerprint.length - 3] & 0xff) << 16)
                | ((long)(fingerprint[fingerprint.length - 2] & 0xff) << 8)
                | ((fingerprint[fingerprint.length - 1] & 0xff));
        }
        else if (publicPk.getVersion() == PublicKeyPacket.VERSION_6)
        {
            this.keyID = ((long) (fingerprint[0] & 0xff) << 56)
                    | ((long)(fingerprint[1] & 0xff) << 48)
                    | ((long)(fingerprint[2] & 0xff) << 40)
                    | ((long) (fingerprint[3] & 0xff) << 32)
                    | ((long) (fingerprint[4] & 0xff) << 24)
                    | ((long) (fingerprint[5] & 0xff) << 16)
                    | ((long) (fingerprint[6] & 0xff) << 8)
                    | ((long) (fingerprint[7] & 0xff));
        }

        // key strength
        if (publicPk.getVersion() >= PublicKeyPacket.VERSION_4)
        {
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
            else if (key instanceof ECPublicBCPGKey)
            {
                ASN1ObjectIdentifier curveOID = ((ECPublicBCPGKey)key).getCurveOID();
                if (curveOID.equals(GNUObjectIdentifiers.Ed25519)
                    || curveOID.equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    this.keyStrength = 256;
                }
                else
                {
                    X9ECParametersHolder ecParameters = ECNamedCurveTable.getByOIDLazy(curveOID);

                    if (ecParameters != null)
                    {
                        this.keyStrength = ecParameters.getCurve().getFieldSize();
                    }
                    else
                    {
                        this.keyStrength = -1; // unknown
                    }
                }
            }
        }
    }

    /**
     * Create a PGP public key from a packet descriptor using the passed in fingerPrintCalculator to do calculate
     * the fingerprint and keyID.
     *
     * @param publicKeyPacket       packet describing the public key.
     * @param fingerPrintCalculator calculator providing the digest support ot create the key fingerprint.
     * @throws PGPException if the packet is faulty, or the required calculations fail.
     */
    public PGPPublicKey(PublicKeyPacket publicKeyPacket, KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        this.publicPk = publicKeyPacket;
        this.ids = new ArrayList<UserDataPacket>();
        this.idSigs = new ArrayList<List<PGPSignature>>();

        init(fingerPrintCalculator);
    }

    /*
     * Constructor for a sub-key.
     */
    PGPPublicKey(
        PublicKeyPacket publicPk,
        TrustPacket trustPk,
        List<PGPSignature> sigs,
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
        List<PGPSignature> subSigs)
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
     *
     * @param pubKey the public key to copy.
     */
    PGPPublicKey(
        PGPPublicKey pubKey)
    {
        this.publicPk = pubKey.publicPk;

        this.keySigs = new ArrayList<PGPSignature>(pubKey.keySigs);
        this.ids = new ArrayList<UserDataPacket>(pubKey.ids);
        this.idTrusts = new ArrayList<TrustPacket>(pubKey.idTrusts);
        this.idSigs = new ArrayList<List<PGPSignature>>(pubKey.idSigs.size());
        for (int i = 0; i != pubKey.idSigs.size(); i++)
        {
            this.idSigs.add(new ArrayList<PGPSignature>((List<PGPSignature>)pubKey.idSigs.get(i)));
        }

        if (pubKey.subSigs != null)
        {
            this.subSigs = new ArrayList<PGPSignature>(pubKey.subSigs.size());
            this.subSigs.addAll(pubKey.subSigs);
        }

        this.fingerprint = pubKey.fingerprint;
        this.keyID = pubKey.keyID;
        this.keyStrength = pubKey.keyStrength;
    }

    PGPPublicKey(
        PublicKeyPacket publicPk,
        TrustPacket trustPk,
        List<PGPSignature> keySigs,
        List<UserDataPacket> ids,
        List<TrustPacket> idTrusts,
        List<List<PGPSignature>> idSigs,
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

    PGPPublicKey(
        PGPPublicKey original,
        TrustPacket trustPk,
        List<PGPSignature> keySigs,
        List<UserDataPacket> ids,
        List<TrustPacket> idTrusts,
        List<List<PGPSignature>> idSigs)
        throws PGPException
    {
        this.publicPk = original.publicPk;
        this.fingerprint = original.fingerprint;
        this.keyStrength = original.keyStrength;
        this.keyID = original.keyID;

        this.trustPk = trustPk;
        this.keySigs = keySigs;
        this.ids = ids;
        this.idTrusts = idTrusts;
        this.idSigs = idSigs;
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
     * @deprecated use getValidSeconds(): greater than version 3 keys may be valid for less than a day.
     */
    public int getValidDays()
    {
        if (publicPk.getVersion() > PublicKeyPacket.VERSION_3)
        {
            long delta = this.getValidSeconds() % (24 * 60 * 60);
            int days = (int)(this.getValidSeconds() / (24 * 60 * 60));

            if (delta > 0 && days == 0)
            {
                return 1;
            }
            else
            {
                return days;
            }
        }
        else
        {
            return publicPk.getValidDays();
        }
    }

    /**
     * Return the trust data associated with the public key, if present.
     *
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
        if (publicPk.getVersion() > PublicKeyPacket.VERSION_3)
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

                seconds = getExpirationTimeFromSig(false, PGPSignature.DIRECT_KEY);
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
        Iterator<PGPSignature> signatures = this.getSignaturesOfType(signatureType);
        long expiryTime = -1;
        long lastDate = -1;

        while (signatures.hasNext())
        {
            PGPSignature sig = (PGPSignature)signatures.next();

            if (!selfSigned || sig.getKeyID() == this.getKeyID())
            {
                PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
                if (hashed == null)
                {
                    continue;
                }

                if (!hashed.hasSubpacket(SignatureSubpacketTags.KEY_EXPIRE_TIME))
                {
                    continue;
                }

                long current = hashed.getKeyExpirationTime();

                if (sig.getKeyID() == this.getKeyID())
                {
                    if (sig.getCreationTime().getTime() > lastDate)
                    {
                        lastDate = sig.getCreationTime().getTime();
                        expiryTime = current;
                    }
                }
                else
                {
                    if (current == 0 || current > expiryTime)
                    {
                        expiryTime = current;
                    }
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
     * Return the fingerprint of the public key.
     *
     * @return key fingerprint.
     */
    public byte[] getFingerprint()
    {
        byte[] tmp = new byte[fingerprint.length];

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
            || (algorithm == ELGAMAL_ENCRYPT) || (algorithm == ELGAMAL_GENERAL)
            || (algorithm == DIFFIE_HELLMAN) || (algorithm == ECDH));
    }

    /**
     * Return true if this could be a master key.
     *
     * @return true if a master key.
     */
    public boolean isMasterKey()
    {
        // this might seem a bit excessive, but we're also trying to flag something can't be a master key.
        return !(publicPk instanceof PublicSubkeyPacket)
            && !(this.isEncryptionKey() && publicPk.getAlgorithm() != PublicKeyAlgorithmTags.RSA_GENERAL);
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
     * @return bit strength of key.
     */
    public int getBitStrength()
    {
        return keyStrength;
    }

    /**
     * Return any userIDs associated with the key.
     *
     * @return an iterator of Strings.
     */
    public Iterator<String> getUserIDs()
    {
        List<String> temp = new ArrayList<String>();

        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof UserIDPacket)
            {
                temp.add(((UserIDPacket)ids.get(i)).getID());
            }
        }

        return temp.iterator();
    }

    /**
     * Return any userIDs associated with the key in raw byte form. No attempt is made
     * to convert the IDs into Strings.
     *
     * @return an iterator of byte[].
     */
    public Iterator<byte[]> getRawUserIDs()
    {
        List<byte[]> temp = new ArrayList<byte[]>();

        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof UserIDPacket)
            {
                temp.add(((UserIDPacket)ids.get(i)).getRawID());
            }
        }

        return temp.iterator();
    }

    /**
     * Return any user attribute vectors associated with the key.
     *
     * @return an iterator of PGPUserAttributeSubpacketVector objects.
     */
    public Iterator<PGPUserAttributeSubpacketVector> getUserAttributes()
    {
        List<PGPUserAttributeSubpacketVector> temp = new ArrayList<PGPUserAttributeSubpacketVector>();

        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof PGPUserAttributeSubpacketVector)
            {
                temp.add((PGPUserAttributeSubpacketVector) ids.get(i));
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
    public Iterator<PGPSignature> getSignaturesForID(
        String id)
    {
        return getSignaturesForID(new UserIDPacket(id));
    }

    /**
     * Return any signatures associated with the passed in id.
     *
     * @param rawID the id to be matched in raw byte form.
     * @return an iterator of PGPSignature objects.
     */
    public Iterator<PGPSignature> getSignaturesForID(
        byte[] rawID)
    {
        return getSignaturesForID(new UserIDPacket(rawID));
    }

    /**
     * Return any signatures associated with the passed in key identifier keyID.
     *
     * @param keyID the key id to be matched.
     * @return an iterator of PGPSignature objects issued by the key with keyID.
     */
    public Iterator<PGPSignature> getSignaturesForKeyID(
        long keyID)
    {
        List<PGPSignature> sigs = new ArrayList<PGPSignature>();

        for (Iterator<PGPSignature> it = getSignatures(); it.hasNext(); )
        {
            PGPSignature sig = (PGPSignature)it.next();

            if (sig.getKeyID() == keyID)
            {
                sigs.add(sig);
            }
        }

        return sigs.iterator();
    }

    private Iterator<PGPSignature> getSignaturesForID(
        UserIDPacket id)
    {
        List<PGPSignature> signatures = new ArrayList<PGPSignature>();
        boolean userIdFound = false;

        for (int i = 0; i != ids.size(); i++)
        {
            if (id.equals(ids.get(i)))
            {
                userIdFound = true;
                signatures.addAll((List<PGPSignature>)idSigs.get(i));
            }
        }

        return userIdFound ? signatures.iterator() : null;
    }

    /**
     * Return an iterator of signatures associated with the passed in user attributes.
     *
     * @param userAttributes the vector of user attributes to be matched.
     * @return an iterator of PGPSignature objects.
     */
    public Iterator<PGPSignature> getSignaturesForUserAttribute(
        PGPUserAttributeSubpacketVector userAttributes)
    {
        List<PGPSignature> signatures = new ArrayList<PGPSignature>();
        boolean attributeFound = false;

        for (int i = 0; i != ids.size(); i++)
        {
            if (userAttributes.equals(ids.get(i)))
            {
                attributeFound = true;
                signatures.addAll((List<PGPSignature>)idSigs.get(i));
            }
        }

        return attributeFound ? signatures.iterator() : null;
    }

    /**
     * Return signatures of the passed in type that are on this key.
     *
     * @param signatureType the type of the signature to be returned.
     * @return an iterator (possibly empty) of signatures of the given type.
     */
    public Iterator<PGPSignature> getSignaturesOfType(
        int signatureType)
    {
        List<PGPSignature> l = new ArrayList<PGPSignature>();
        Iterator<PGPSignature> it = this.getSignatures();

        while (it.hasNext())
        {
            PGPSignature sig = (PGPSignature)it.next();

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
    public Iterator<PGPSignature> getSignatures()
    {
        if (subSigs == null)
        {
            List<PGPSignature> sigs = new ArrayList<PGPSignature>(keySigs);

            for (int i = 0; i != idSigs.size(); i++)
            {
                sigs.addAll((List<PGPSignature>)idSigs.get(i));
            }

            return sigs.iterator();
        }
        else
        {
            return subSigs.iterator();
        }
    }

    /**
     * Return all signatures/certifications directly associated with this key (ie, not to a user id).
     *
     * @return an iterator (possibly empty) with all signatures/certifications.
     */
    public Iterator<PGPSignature> getKeySignatures()
    {
        if (subSigs == null)
        {
            List<PGPSignature> sigs = new ArrayList<PGPSignature>(keySigs);

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
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut, false);

        return bOut.toByteArray();
    }

    /**
     * Return an encoding of the key, with trust packets stripped out if forTransfer is true.
     *
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @return a encoded byte array representing the key.
     * @throws IOException in case of encoding error.
     */
    public byte[] getEncoded(boolean forTransfer)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut, forTransfer);

        return bOut.toByteArray();
    }

    public void encode(
        OutputStream outStream)
        throws IOException
    {
        encode(outStream, false);
    }

    /**
     * Encode the key to outStream, with trust packets stripped out if forTransfer is true.
     *
     * @param outStream   stream to write the key encoding to.
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @throws IOException in case of encoding error.
     */
    public void encode(OutputStream outStream, boolean forTransfer)
        throws IOException
    {
        BCPGOutputStream out = BCPGOutputStream.wrap(outStream);

        out.writePacket(publicPk);
        if (!forTransfer && trustPk != null)
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
                if (ids.get(i) instanceof UserIDPacket)
                {
                    UserIDPacket id = (UserIDPacket)ids.get(i);

                    out.writePacket(id);
                }
                else
                {
                    PGPUserAttributeSubpacketVector v = (PGPUserAttributeSubpacketVector)ids.get(i);

                    out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
                }

                if (!forTransfer && idTrusts.get(i) != null)
                {
                    out.writePacket((TrustPacket)idTrusts.get(i));
                }

                List<PGPSignature> sigs = (List<PGPSignature>)idSigs.get(i);
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((PGPSignature)sigs.get(j)).encode(out, forTransfer);
                }
            }
        }
        else
        {
            for (int j = 0; j != subSigs.size(); j++)
            {
                ((PGPSignature)subSigs.get(j)).encode(out, forTransfer);
            }
        }
    }

    /**
     * Check whether this (sub)key has a revocation signature on it.
     *
     * @return boolean indicating whether this (sub)key has been revoked.
     * @deprecated this method is poorly named, use hasRevocation().
     */
    public boolean isRevoked()
    {
        return hasRevocation();
    }

    /**
     * Check whether this (sub)key has a revocation signature on it.
     *
     * @return boolean indicating whether this (sub)key has had a (possibly invalid) revocation attached..
     */
    public boolean hasRevocation()
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
     * @param key           the key the certification is to be added to.
     * @param rawID         the raw bytes making up the user id..
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey key,
        byte[] rawID,
        PGPSignature certification)
    {
        return addCert(key, new UserIDPacket(rawID), certification);
    }

    /**
     * Add a certification for an id to the given public key.
     *
     * @param key           the key the certification is to be added to.
     * @param id            the id the certification is associated with.
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey key,
        String id,
        PGPSignature certification)
    {
        return addCert(key, new UserIDPacket(id), certification);
    }

    /**
     * Add a certification for the given UserAttributeSubpackets to the given public key.
     *
     * @param key            the key the certification is to be added to.
     * @param userAttributes the attributes the certification is associated with.
     * @param certification  the new certification.
     * @return the re-certified key.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey key,
        PGPUserAttributeSubpacketVector userAttributes,
        PGPSignature certification)
    {
        return addCert(key, userAttributes, certification);
    }

    private static PGPPublicKey addCert(
        PGPPublicKey key,
        UserDataPacket id,
        PGPSignature certification)
    {
        PGPPublicKey returnKey = new PGPPublicKey(key);
        List<PGPSignature> sigList = null;

        for (int i = 0; i != returnKey.ids.size(); i++)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                sigList = (List<PGPSignature>)returnKey.idSigs.get(i);
            }
        }

        if (sigList != null)
        {
            sigList.add(certification);
        }
        else
        {
            sigList = new ArrayList<PGPSignature>();

            sigList.add(certification);
            returnKey.ids.add(id);
            returnKey.idTrusts.add(null);
            returnKey.idSigs.add(sigList);
        }

        return returnKey;
    }

    /**
     * Remove any certifications associated with a given user attribute subpacket
     * on a key.
     *
     * @param key            the key the certifications are to be removed from.
     * @param userAttributes the attributes to be removed.
     * @return the re-certified key, null if the user attribute subpacket was not found on the key.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        PGPUserAttributeSubpacketVector userAttributes)
    {
        return removeCert(key, userAttributes);
    }

    /**
     * Remove any certifications associated with a given id on a key.
     *
     * @param key the key the certifications are to be removed from.
     * @param id  the id that is to be removed.
     * @return the re-certified key, null if the id was not found on the key.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        String id)
    {
        return removeCert(key, new UserIDPacket(id));
    }

    /**
     * Remove any certifications associated with a given id on a key.
     *
     * @param key   the key the certifications are to be removed from.
     * @param rawID the id that is to be removed in raw byte form.
     * @return the re-certified key, null if the id was not found on the key.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        byte[] rawID)
    {
        return removeCert(key, new UserIDPacket(rawID));
    }

    private static PGPPublicKey removeCert(
        PGPPublicKey key,
        UserDataPacket id)
    {
        PGPPublicKey returnKey = new PGPPublicKey(key);
        boolean found = false;

        for (int i = returnKey.ids.size() - 1; i >= 0; i--)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                found = true;
                returnKey.ids.remove(i);
                returnKey.idTrusts.remove(i);
                returnKey.idSigs.remove(i);
            }
        }

        return found ? returnKey : null;
    }

    /**
     * Remove a certification associated with a given id on a key.
     *
     * @param key           the key the certifications are to be removed from.
     * @param id            the id that the certification is to be removed from (in its raw byte form)
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        byte[] id,
        PGPSignature certification)
    {
        return removeCert(key, new UserIDPacket(id), certification);
    }

    /**
     * Remove a certification associated with a given id on a key.
     *
     * @param key           the key the certifications are to be removed from.
     * @param id            the id that the certification is to be removed from.
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        String id,
        PGPSignature certification)
    {
        return removeCert(key, new UserIDPacket(id), certification);
    }

    /**
     * Remove a certification associated with a given user attributes on a key.
     *
     * @param key            the key the certifications are to be removed from.
     * @param userAttributes the user attributes that the certification is to be removed from.
     * @param certification  the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        PGPUserAttributeSubpacketVector userAttributes,
        PGPSignature certification)
    {
        return removeCert(key, userAttributes, certification);
    }

    private static PGPPublicKey removeCert(
        PGPPublicKey key,
        UserDataPacket id,
        PGPSignature certification)
    {
        PGPPublicKey returnKey = new PGPPublicKey(key);
        boolean found = false;

        for (int i = 0; i < returnKey.ids.size(); i++)
        {
            if (id.equals(returnKey.ids.get(i)))
            {
                found |= ((List<PGPSignature>)returnKey.idSigs.get(i)).remove(certification);
            }
        }

        return found ? returnKey : null;
    }

    /**
     * Add a revocation or some other key certification to a key.
     *
     * @param key           the key the revocation is to be added to.
     * @param certification the key signature to be added.
     * @return the new changed public key object.
     */
    public static PGPPublicKey addCertification(
        PGPPublicKey key,
        PGPSignature certification)
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

        PGPPublicKey returnKey = new PGPPublicKey(key);
        List<PGPSignature> sigs = returnKey.subSigs != null ? returnKey.subSigs : returnKey.keySigs;

        sigs.add(certification);

        return returnKey;
    }

    /**
     * Remove a certification from the key.
     *
     * @param key           the key the certifications are to be removed from.
     * @param certification the certification to be removed.
     * @return the modified key, null if the certification was not found.
     */
    public static PGPPublicKey removeCertification(
        PGPPublicKey key,
        PGPSignature certification)
    {
        PGPPublicKey returnKey = new PGPPublicKey(key);
        List<PGPSignature> sigs = returnKey.subSigs != null ? returnKey.subSigs : returnKey.keySigs;

        boolean found = sigs.remove(certification);

        for (Iterator<List<PGPSignature>> it = returnKey.idSigs.iterator(); it.hasNext(); )
        {
            List<PGPSignature> idSigs = (List<PGPSignature>)it.next();
            found |= idSigs.remove(certification);
        }

        return found ? returnKey : null;
    }

    /**
     * Merge this the given local public key with another, potentially fresher copy.
     * The resulting {@link PGPPublicKey} contains the sum of both keys user-ids and signatures.
     * <p>
     * If joinTrustPackets is set to true and the copy carries a trust packet,
     * the joined key will copy the trust-packet from the copy.
     * Otherwise, it will carry the trust packet of the local key.
     *
     * @param key                        local public key
     * @param copy                       copy of the public key (e.g. from a key server)
     * @param joinTrustPackets           if true, trust packets from the copy are copied over into the resulting key
     * @param allowSubkeySigsOnNonSubkey if true, subkey signatures on the copy will be present in the merged key, even if key was not a subkey before.
     * @return joined key
     * @throws PGPException
     */
    public static PGPPublicKey join(
        PGPPublicKey key,
        PGPPublicKey copy,
        boolean joinTrustPackets,
        boolean allowSubkeySigsOnNonSubkey)
        throws PGPException
    {
        if (key.getKeyID() != copy.getKeyID())
        {
            throw new IllegalArgumentException("Key-ID mismatch.");
        }

        TrustPacket trustPk = key.trustPk;
        List<PGPSignature> keySigs = new ArrayList<PGPSignature>(key.keySigs);
        List<UserDataPacket> ids = new ArrayList<UserDataPacket>(key.ids);
        List<TrustPacket> idTrusts = new ArrayList<TrustPacket>(key.idTrusts);
        List<List<PGPSignature>> idSigs = new ArrayList<List<PGPSignature>>(key.idSigs);
        List<PGPSignature> subSigs = key.subSigs == null ? null : new ArrayList<PGPSignature>(key.subSigs);

        if (joinTrustPackets)
        {
            if (copy.trustPk != null)
            {
                trustPk = copy.trustPk;
            }
        }

        // key signatures
        for (Iterator<PGPSignature> it = copy.keySigs.iterator(); it.hasNext();)
        {
            PGPSignature keySig = (PGPSignature)it.next();
            boolean found = false;
            for (int i = 0; i < keySigs.size(); i++)
            {
                PGPSignature existingKeySig = (PGPSignature)keySigs.get(i);
                if (PGPSignature.isSignatureEncodingEqual(existingKeySig, keySig))
                {
                    found = true;
                    // join existing sig with copy to apply modifications in unhashed subpackets
                    existingKeySig = PGPSignature.join(existingKeySig, keySig);
                    keySigs.set(i, existingKeySig);
                    break;
                }
            }
            if (found)
            {
                break;
            }
            keySigs.add(keySig);
        }

        // user-ids and id sigs
        for (int idIdx = 0; idIdx < copy.ids.size(); idIdx++)
        {
            UserDataPacket copyId = (UserDataPacket)copy.ids.get(idIdx);
            List<PGPSignature> copyIdSigs = new ArrayList<PGPSignature>((List<PGPSignature>)copy.idSigs.get(idIdx));
            TrustPacket copyTrust = (TrustPacket)copy.idTrusts.get(idIdx);

            int existingIdIndex = -1;
            for (int i = 0; i < ids.size(); i++)
            {
                UserDataPacket existingId = (UserDataPacket)ids.get(i);
                if (existingId.equals(copyId))
                {
                    existingIdIndex = i;
                    break;
                }
            }

            // new user-id
            if (existingIdIndex == -1)
            {
                ids.add(copyId);
                idSigs.add(copyIdSigs);
                idTrusts.add(joinTrustPackets ? copyTrust : null);
                continue;
            }

            // existing user-id
            if (joinTrustPackets && copyTrust != null)
            {
                TrustPacket existingTrust = (TrustPacket)idTrusts.get(existingIdIndex);
                if (existingTrust == null || Arrays.areEqual(copyTrust.getLevelAndTrustAmount(), existingTrust.getLevelAndTrustAmount()))
                {
                    idTrusts.set(existingIdIndex, copyTrust);
                }
            }

            List<PGPSignature> existingIdSigs = (List<PGPSignature>)idSigs.get(existingIdIndex);
            for (Iterator<PGPSignature> it = copyIdSigs.iterator(); it.hasNext();)
            {
                PGPSignature newSig = (PGPSignature)it.next();
                boolean found = false;
                for (int i = 0; i < existingIdSigs.size(); i++)
                {
                    PGPSignature existingSig = (PGPSignature)existingIdSigs.get(i);
                    if (PGPSignature.isSignatureEncodingEqual(newSig, existingSig))
                    {
                        found = true;
                        // join existing sig with copy to apply modifications in unhashed subpackets
                        existingSig = PGPSignature.join(existingSig, newSig);
                        existingIdSigs.set(i, existingSig);
                        break;
                    }
                }
                if (!found)
                {
                    existingIdSigs.add(newSig);
                }
            }
        }

        // subSigs
        if (copy.subSigs != null)
        {
            if (subSigs == null && allowSubkeySigsOnNonSubkey)
            {
                subSigs = new ArrayList<PGPSignature>(copy.subSigs);
            }
            else
            {
                for (Iterator<PGPSignature> it = copy.subSigs.iterator(); it.hasNext();)
                {
                    PGPSignature copySubSig = (PGPSignature)it.next();
                    boolean found = false;
                    for (int i = 0; subSigs != null && i < subSigs.size(); i++)
                    {
                        PGPSignature existingSubSig = (PGPSignature)subSigs.get(i);
                        if (PGPSignature.isSignatureEncodingEqual(existingSubSig, copySubSig))
                        {
                            found = true;
                            // join existing sig with copy to apply modifications in unhashed subpackets
                            existingSubSig = PGPSignature.join(existingSubSig, copySubSig);
                            subSigs.set(i, existingSubSig);
                            break;
                        }
                    }
                    if (!found && subSigs != null)
                    {
                        subSigs.add(copySubSig);
                    }
                }
            }
        }

        PGPPublicKey merged = new PGPPublicKey(key, trustPk, keySigs, ids, idTrusts, idSigs);
        merged.subSigs = subSigs;

        return merged;
    }
}
