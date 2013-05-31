package org.bouncycastle.openpgp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.PublicSubkeyPacket;
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
     * @param id
     * @param checksumCalculator
     * @param hashedPcks
     * @param unhashedPcks
     * @param keySignerBuilder
     * @param keyEncryptor
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
            
            keys.add(new PGPSecretKey(keyPair.getPrivateKey(), new PGPPublicKey(keyPair.getPublicKey(), null, subSigs), checksumCalculator, keyEncryptor));
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
            PGPPublicKey k = new PGPPublicKey(((PGPSecretKey)it.next()).getPublicKey());
            
            k.publicPk = new PublicSubkeyPacket(k.getAlgorithm(), k.getCreationTime(), k.publicPk.getKey());
            
            pubKeys.add(k);
        }
        
        return new PGPPublicKeyRing(pubKeys);
    }
}
