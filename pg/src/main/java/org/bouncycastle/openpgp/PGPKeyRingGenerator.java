package org.bouncycastle.openpgp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * Generator for a PGP master and subkey ring. This class will generate
 * both the secret and public key rings
 */
public class PGPKeyRingGenerator
{    
    List                                keys = new ArrayList();

    private PBESecretKeyEncryptor       keyEncryptor;
    private PGPDigestCalculator checksumCalculator;
    private PGPKeyPair                  masterKey;
    private PGPSignatureSubpacketVector hashedPcks;
    private PGPSignatureSubpacketVector unhashedPcks;
    private PGPContentSignerBuilder     keySignerBuilder;

    /**
     * Create a new key ring generator.
     *
     * @param certificationLevel
     * @param masterKey
     * @param id id to associate with the key.
     * @param checksumCalculator key checksum calculator
     * @param hashedPcks
     * @param unhashedPcks
     * @param keySignerBuilder builder for key certifications - will be initialised with master secret key.
     * @param keyEncryptor encryptor for secret subkeys.
     * @throws PGPException
     */
    public PGPKeyRingGenerator(
        int                            certificationLevel,
        PGPKeyPair                     masterKey,
        String                         id,
        PGPDigestCalculator checksumCalculator,
        PGPSignatureSubpacketVector    hashedPcks,
        PGPSignatureSubpacketVector    unhashedPcks,
        PGPContentSignerBuilder        keySignerBuilder,
        PBESecretKeyEncryptor          keyEncryptor)
        throws PGPException
    {
        this.masterKey = masterKey;
        this.keyEncryptor = keyEncryptor;
        this.checksumCalculator = checksumCalculator;
        this.keySignerBuilder = keySignerBuilder;
        this.hashedPcks = hashedPcks;
        this.unhashedPcks = unhashedPcks;

        keys.add(new PGPSecretKey(certificationLevel, masterKey, id, checksumCalculator, hashedPcks, unhashedPcks, keySignerBuilder, keyEncryptor));
    }

    /**
     * Create a new key ring generator based on an original secret key ring. The default hashed/unhashed sub-packets
     * for subkey signatures will be inherited from the first signature on the master key (other than CREATION-TIME
     * which will be ignored).
     *
     * @param originalSecretRing the secret key ring we want to add a subkeyto,
     * @param secretKeyDecryptor a decryptor for the signing master key.
     * @param checksumCalculator key checksum calculator
     * @param keySignerBuilder builder for key certifications - will be initialised with master secret key.
     * @param keyEncryptor encryptor for secret subkeys.
     * @throws PGPException
     */
    public PGPKeyRingGenerator(
        PGPSecretKeyRing            originalSecretRing,
        PBESecretKeyDecryptor       secretKeyDecryptor,
        PGPDigestCalculator         checksumCalculator,
        PGPContentSignerBuilder     keySignerBuilder,
        PBESecretKeyEncryptor       keyEncryptor)
        throws PGPException
    {
        this.masterKey = new PGPKeyPair(originalSecretRing.getPublicKey(),
            originalSecretRing.getSecretKey().extractPrivateKey(secretKeyDecryptor));
        this.keyEncryptor = keyEncryptor;
        this.checksumCalculator = checksumCalculator;
        this.keySignerBuilder = keySignerBuilder;

        PGPSignature certSig = (PGPSignature)originalSecretRing.getPublicKey().getSignatures().next();
        List hashedVec = new ArrayList();
        PGPSignatureSubpacketVector existing = certSig.getHashedSubPackets();
        for (int i = 0; i != existing.size(); i++)
        {
            if (existing.packets[i].getType() == SignatureSubpacketTags.CREATION_TIME)
            {
                continue;
            }
            hashedVec.add(existing.packets[i]);
        }
        this.hashedPcks = new PGPSignatureSubpacketVector(
            (SignatureSubpacket[])hashedVec.toArray(new SignatureSubpacket[hashedVec.size()]));
        this.unhashedPcks = certSig.getUnhashedSubPackets();

        keys.addAll(originalSecretRing.keys);
    }

    /**
     * Add a sub key to the key ring to be generated with default certification and inheriting
     * the hashed/unhashed packets of the master key.
     * 
     * @param keyPair
     * @throws PGPException
     */
    public void addSubKey(
        PGPKeyPair    keyPair) 
        throws PGPException
    {
        addSubKey(keyPair, hashedPcks, unhashedPcks);
    }
    
    /**
     * Add a subkey with specific hashed and unhashed packets associated with it and default
     * certification. 
     * 
     * @param keyPair public/private key pair.
     * @param hashedPcks hashed packet values to be included in certification.
     * @param unhashedPcks unhashed packets values to be included in certification.
     * @throws PGPException
     */
    public void addSubKey(
        PGPKeyPair                  keyPair,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks) 
        throws PGPException
    {
        try
        {
            //
            // generate the certification
            //
            PGPSignatureGenerator  sGen = new PGPSignatureGenerator(keySignerBuilder);

            sGen.init(PGPSignature.SUBKEY_BINDING, masterKey.getPrivateKey());

            sGen.setHashedSubpackets(hashedPcks);
            sGen.setUnhashedSubpackets(unhashedPcks);

            List                 subSigs = new ArrayList();
            
            subSigs.add(sGen.generateCertification(masterKey.getPublicKey(), keyPair.getPublicKey()));

            // replace the public key packet structure with a public subkey one.
            PGPPublicKey pubSubKey = new PGPPublicKey(keyPair.getPublicKey(), null, subSigs);

            pubSubKey.publicPk = new PublicSubkeyPacket(pubSubKey.getAlgorithm(), pubSubKey.getCreationTime(), pubSubKey.publicPk.getKey());

            keys.add(new PGPSecretKey(keyPair.getPrivateKey(), pubSubKey, checksumCalculator, keyEncryptor));
        }
        catch (PGPException e)
        {
            throw e;
        } 
        catch (Exception e)
        {
            throw new PGPException("exception adding subkey: ", e);
        }
    }
    
    /**
     * Return the secret key ring.
     * 
     * @return a secret key ring.
     */
    public PGPSecretKeyRing generateSecretKeyRing()
    {
        return new PGPSecretKeyRing(keys);
    }
    
    /**
     * Return the public key ring that corresponds to the secret key ring.
     * 
     * @return a public key ring.
     */
    public PGPPublicKeyRing generatePublicKeyRing()
    {
        Iterator it = keys.iterator();
        List     pubKeys = new ArrayList();
        
        pubKeys.add(((PGPSecretKey)it.next()).getPublicKey());
        
        while (it.hasNext())
        {
            pubKeys.add(((PGPSecretKey)it.next()).getPublicKey());
        }
        
        return new PGPPublicKeyRing(pubKeys);
    }
}
