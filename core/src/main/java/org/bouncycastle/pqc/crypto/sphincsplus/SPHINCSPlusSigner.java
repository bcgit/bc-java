package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * SPHINCS+ signer.
 * <p>
 *     This version is based on the 3rd submission with deference to the updated reference
 *     implementation on github as at November 9th 2021. This version includes the changes
 *     for the countermeasure for the long-message second preimage attack - see
 *     "https://github.com/sphincs/sphincsplus/commit/61cd2695c6f984b4f4d6ed675378ed9a486cbede"
 *     for further details.
 * </p>
 */
public class SPHINCSPlusSigner
    implements MessageSigner
{
    private SPHINCSPlusPrivateKeyParameters privKey;
    private SPHINCSPlusPublicKeyParameters pubKey;

    private SecureRandom random;

    /**
     * Base constructor.
     */
    public SPHINCSPlusSigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = ((SPHINCSPlusPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                this.random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (SPHINCSPlusPrivateKeyParameters)param;
            }
        }
        else
        {
            pubKey = (SPHINCSPlusPublicKeyParameters)param;
        }
    }

    public byte[] generateSignature(byte[] message)
    {
//        # Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
//        # Output: SPHINCS+ signature SIG
        // init

        SPHINCSPlusEngine engine = privKey.getParameters().getEngine();

        engine.init(privKey.pk.seed);

        // generate randomizer
        byte[] optRand = new byte[engine.N];
        if (random != null)
        {
            random.nextBytes(optRand);
        }
        else
        {
            System.arraycopy(privKey.pk.seed, 0, optRand, 0, optRand.length);
        }

        Fors fors = new Fors(engine); 
        byte[] R = engine.PRF_msg(privKey.sk.prf, optRand, message);

        // compute message digest and index
        IndexedDigest idxDigest = engine.H_msg(R, privKey.pk.seed, privKey.pk.root, message);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;
        // FORS sign
        ADRS adrs = new ADRS();
        adrs.setType(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        SIG_FORS[] sig_fors = fors.sign(mHash, privKey.sk.seed, privKey.pk.seed, adrs);
        // get FORS public key - spec shows M?
        adrs = new ADRS();
        adrs.setType(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = fors.pkFromSig(sig_fors, mHash, privKey.pk.seed, adrs);

        // sign FORS public key with HT
        ADRS treeAdrs = new ADRS();
        treeAdrs.setType(ADRS.TREE);

        HT ht = new HT(engine, privKey.getSeed(), privKey.getPublicSeed());
        byte[] SIG_HT = ht.sign(PK_FORS, idx_tree, idx_leaf);

        byte[][] sigComponents = new byte[sig_fors.length + 2][];
        sigComponents[0] = R;

        for (int i = 0; i != sig_fors.length; i++)
        {
            sigComponents[1 + i] = Arrays.concatenate(sig_fors[i].sk, Arrays.concatenate(sig_fors[i].authPath));
        }
        sigComponents[sigComponents.length - 1] = SIG_HT;

        return Arrays.concatenate(sigComponents);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        //# Input: Message M, signature SIG, public key PK
        //# Output: Boolean

        // init
        SPHINCSPlusEngine engine = pubKey.getParameters().getEngine();

        engine.init(pubKey.getSeed());

        ADRS adrs = new ADRS();
        SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);

        byte[] R = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] SIG_HT = sig.getSIG_HT();

        // compute message digest and index
        IndexedDigest idxDigest = engine.H_msg(R, pubKey.getSeed(), pubKey.getRoot(), message);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;

        // compute FORS public key
        adrs.setType(ADRS.FORS_TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = new Fors(engine).pkFromSig(sig_fors, mHash, pubKey.getSeed(), adrs);
        // verify HT signature
        adrs.setType(ADRS.TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        HT ht = new HT(engine, null, pubKey.getSeed());
        return ht.verify(PK_FORS, SIG_HT, pubKey.getSeed(), idx_tree, idx_leaf, pubKey.getRoot());
    }
}

