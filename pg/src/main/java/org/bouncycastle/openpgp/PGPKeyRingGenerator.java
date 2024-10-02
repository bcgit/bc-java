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
 * Generator for a PGP primary and subkey ring. This class will generate
 * both the secret and public key rings
 */
public class PGPKeyRingGenerator
{    
    private final List<PGPSecretKey>          keys = new ArrayList<PGPSecretKey>();

    private final PBESecretKeyEncryptor       keyEncryptor;
    private final PGPDigestCalculator         checksumCalculator;
    private final PGPKeyPair                  primaryKey;
    private final PGPSignatureSubpacketVector hashedPcks;
    private final PGPSignatureSubpacketVector unhashedPcks;
    private final PGPContentSignerBuilder     keySignerBuilder;

    /**
     * Create a new key ring generator.
     *
     * @param certificationLevel certification level for user-ids
     * @param primaryKey primary key
     * @param id id to associate with the key.
     * @param checksumCalculator key checksum calculator
     * @param hashedPcks hashed signature subpackets
     * @param unhashedPcks unhashed signature subpackets
     * @param keySignerBuilder builder for key certifications - will be initialised with primary secret key.
     * @param keyEncryptor encryptor for secret subkeys.
     * @throws PGPException error during signature generation
     */
    public PGPKeyRingGenerator(
        int                            certificationLevel,
        PGPKeyPair                     primaryKey,
        String                         id,
        PGPDigestCalculator checksumCalculator,
        PGPSignatureSubpacketVector    hashedPcks,
        PGPSignatureSubpacketVector    unhashedPcks,
        PGPContentSignerBuilder        keySignerBuilder,
        PBESecretKeyEncryptor          keyEncryptor)
        throws PGPException
    {
        this.primaryKey = primaryKey;
        this.keyEncryptor = keyEncryptor;
        this.checksumCalculator = checksumCalculator;
        this.keySignerBuilder = keySignerBuilder;
        this.hashedPcks = hashedPcks;
        this.unhashedPcks = unhashedPcks;

        keys.add(new PGPSecretKey(certificationLevel, primaryKey, id, checksumCalculator, hashedPcks, unhashedPcks, keySignerBuilder, keyEncryptor));
    }

    /**
     * Create a new key ring generator without a user-id, but instead with a primary key carrying a direct-key signature.
     * @param primaryKey primary key
     * @param checksumCalculator checksum calculator
     * @param hashedPcks hashed signature subpackets
     * @param unhashedPcks unhashed signature subpackets
     * @param keySignerBuilder signer builder
     * @param keyEncryptor key encryptor
     * @throws PGPException error during signature generation
     */
    public PGPKeyRingGenerator(
            PGPKeyPair primaryKey,
            PGPDigestCalculator checksumCalculator,
            PGPSignatureSubpacketVector hashedPcks,
            PGPSignatureSubpacketVector unhashedPcks,
            PGPContentSignerBuilder keySignerBuilder,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {
        this.primaryKey = primaryKey;
        this.keyEncryptor = keyEncryptor;
        this.checksumCalculator = checksumCalculator;
        this.keySignerBuilder = keySignerBuilder;
        this.hashedPcks = hashedPcks;
        this.unhashedPcks = unhashedPcks;

        PGPSignatureGenerator sigGen;

        try
        {
            sigGen = new PGPSignatureGenerator(keySignerBuilder, primaryKey.getPublicKey());
        }
        catch (Exception e)
        {
            throw new PGPException("creating signature generator: " + e, e);
        }

        // Keyring without user-id needs direct key sig
        sigGen.init(PGPSignature.DIRECT_KEY, primaryKey.getPrivateKey());
        sigGen.setHashedSubpackets(hashedPcks);
        sigGen.setUnhashedSubpackets(unhashedPcks);

        PGPSecretKey secretKey = new PGPSecretKey(primaryKey.getPrivateKey(), primaryKey.getPublicKey(), checksumCalculator, true, keyEncryptor);
        PGPPublicKey publicKey = secretKey.getPublicKey();
        try
        {
            PGPSignature certification = sigGen.generateCertification(primaryKey.getPublicKey());

            publicKey = PGPPublicKey.addCertification(publicKey, certification);
        }
        catch (Exception e)
        {
            throw new PGPException("exception doing direct-key signature: " + e, e);
        }
        secretKey = PGPSecretKey.replacePublicKey(secretKey, publicKey);

        keys.add(secretKey);
    }


    /**
     * Create a new key ring generator based on an original secret key ring. The default hashed/unhashed sub-packets
     * for subkey signatures will be inherited from the first signature on the primary key (other than CREATION-TIME
     * which will be ignored).
     *
     * @param originalSecretRing the secret key ring we want to add a subkeyto,
     * @param secretKeyDecryptor a decryptor for the signing primary key.
     * @param checksumCalculator key checksum calculator
     * @param keySignerBuilder builder for key certifications - will be initialised with primary secret key.
     * @param keyEncryptor encryptor for secret subkeys.
     * @throws PGPException error during signature generation
     */
    public PGPKeyRingGenerator(
        PGPSecretKeyRing            originalSecretRing,
        PBESecretKeyDecryptor       secretKeyDecryptor,
        PGPDigestCalculator         checksumCalculator,
        PGPContentSignerBuilder     keySignerBuilder,
        PBESecretKeyEncryptor       keyEncryptor)
        throws PGPException
    {
        this.primaryKey = new PGPKeyPair(originalSecretRing.getPublicKey(),
            originalSecretRing.getSecretKey().extractPrivateKey(secretKeyDecryptor));
        this.keyEncryptor = keyEncryptor;
        this.checksumCalculator = checksumCalculator;
        this.keySignerBuilder = keySignerBuilder;

        PGPSignature certSig = (PGPSignature)originalSecretRing.getPublicKey().getSignatures().next();
        List<SignatureSubpacket> hashedVec = new ArrayList<SignatureSubpacket>();
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
     * the hashed/unhashed packets of the primary key.
     * 
     * @param keyPair the key pair to add.
     * @throws PGPException error during signature generation
     */
    public void addSubKey(
        PGPKeyPair    keyPair) 
        throws PGPException
    {
        addSubKey(keyPair, hashedPcks, unhashedPcks);
    }

    /**
     * Add a sub key to the key ring to be generated with default certification and inheriting
     * the hashed/unhashed packets of the primary key.  If bindingSignerBldr is not null it will be used to add a Primary Key Binding
     * signature (type 0x19) into the hashedPcks for the key (required for signing subkeys).
     *
     * @param keyPair the key pair to add.
     * @param bindingSignerBldr provide a signing builder to create the Primary Key signature.
     * @throws PGPException error during signature generation
     */
    public void addSubKey(
        PGPKeyPair    keyPair,
        PGPContentSignerBuilder     bindingSignerBldr)
        throws PGPException
    {
        addSubKey(keyPair, hashedPcks, unhashedPcks, bindingSignerBldr);
    }

    /**
     * Add a subkey with specific hashed and unhashed packets associated with it and default
     * certification.
     *
     * @param keyPair public/private key pair.
     * @param hashedPcks hashed packet values to be included in certification.
     * @param unhashedPcks unhashed packets values to be included in certification.
     * @throws PGPException error during signature generation
     */
    public void addSubKey(
        PGPKeyPair                  keyPair,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks)
        throws PGPException
    {
        addSubKey(keyPair, hashedPcks, unhashedPcks, null);
    }

    /**
     * Add a subkey with specific hashed and unhashed packets associated with it and default
     * certification. If bindingSignerBldr is not null it will be used to add a Primary Key Binding
     * signature (type 0x19) into the hashedPcks for the key (required for signing subkeys).
     * 
     * @param keyPair public/private key pair.
     * @param hashedPcks hashed packet values to be included in certification.
     * @param unhashedPcks unhashed packets values to be included in certification.
     * @param bindingSignerBldr provide a signing builder to create the Primary Key signature.
     * @throws PGPException error during signature generation
     */
    public void addSubKey(
        PGPKeyPair                  keyPair,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        PGPContentSignerBuilder     bindingSignerBldr)
        throws PGPException
    {
        try
        {
            //
            // generate the certification
            //
            PGPSignatureGenerator  sGen = new PGPSignatureGenerator(keySignerBuilder, primaryKey.getPublicKey());

            sGen.init(PGPSignature.SUBKEY_BINDING, primaryKey.getPrivateKey());

            if (bindingSignerBldr != null)
            {
                // add primary key binding
                PGPSignatureGenerator  pGen = new PGPSignatureGenerator(bindingSignerBldr, keyPair.getPublicKey());

                pGen.init(PGPSignature.PRIMARYKEY_BINDING, keyPair.getPrivateKey());

                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator(hashedPcks);

                spGen.addEmbeddedSignature(false,
                        pGen.generateCertification(primaryKey.getPublicKey(), keyPair.getPublicKey()));
                sGen.setHashedSubpackets(spGen.generate());
            }
            else
            {
                sGen.setHashedSubpackets(hashedPcks);
            }

            sGen.setUnhashedSubpackets(unhashedPcks);

            List<PGPSignature> subSigs = new ArrayList<PGPSignature>();
            
            subSigs.add(sGen.generateCertification(primaryKey.getPublicKey(), keyPair.getPublicKey()));

            // replace the public key packet structure with a public subkey one.
            PGPPublicKey pubSubKey = new PGPPublicKey(keyPair.getPublicKey(), null, subSigs);

            pubSubKey.publicPk = new PublicSubkeyPacket(pubSubKey.getVersion(), pubSubKey.getAlgorithm(), pubSubKey.getCreationTime(), pubSubKey.publicPk.getKey());

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
        Iterator<PGPSecretKey> it = keys.iterator();
        List<PGPPublicKey> pubKeys = new ArrayList<PGPPublicKey>();

        pubKeys.add((it.next()).getPublicKey());

        while (it.hasNext())
        {
            pubKeys.add((it.next()).getPublicKey());
        }
        
        return new PGPPublicKeyRing(pubKeys);
    }
}
