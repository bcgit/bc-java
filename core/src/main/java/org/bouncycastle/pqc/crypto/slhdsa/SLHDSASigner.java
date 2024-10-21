package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * SLH-DA signer.
 * <p>
 * This version is based on the 3rd submission with deference to the updated reference
 * implementation on github as at November 9th 2021. This version includes the changes
 * for the countermeasure for the long-message second preimage attack - see
 * "https://github.com/sphincs/sphincsplus/commit/61cd2695c6f984b4f4d6ed675378ed9a486cbede"
 * for further details.
 * </p>
 */
public class SLHDSASigner
    implements MessageSigner
{
    private static final byte[] DEFAULT_PREFIX = new byte[]{ 0, 0 };

    private byte[] msgPrefix;
    private SLHDSAPublicKeyParameters pubKey;
    private SLHDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    /**
     * Base constructor.
     */
    public SLHDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (param instanceof ParametersWithContext)
        {
            ParametersWithContext withContext = (ParametersWithContext)param;
            param = withContext.getParameters();

            int ctxLength = withContext.getContextLength();
            if (ctxLength > 255)
            {
                throw new IllegalArgumentException("context too long");
            }

            msgPrefix = new byte[2 + ctxLength];
            msgPrefix[0] = 0;
            msgPrefix[1] = (byte)ctxLength;
            withContext.copyContextTo(msgPrefix, 2, ctxLength);
        }
        else
        {
            msgPrefix = DEFAULT_PREFIX;
        }

        SLHDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (SLHDSAPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (SLHDSAPrivateKeyParameters)param;
                random = null;
            }

            parameters = privKey.getParameters();
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            parameters = pubKey.getParameters();
        }

        if (parameters.isPreHash())
        {
            throw new IllegalArgumentException("\"pure\" slh-dsa must use non pre-hash parameters");
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        // TODO Redundant with the engine created in internalGenerateSignature
        SLHDSAEngine engine = privKey.getParameters().getEngine();

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

        return internalGenerateSignature(privKey, msgPrefix, message, optRand);
    }

    // Equivalent to slh_verify_internal from specs
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return internalVerifySignature(pubKey, msgPrefix, message, signature);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        return internalVerifySignature(pubKey, null, message, signature);
    }

    private static boolean internalVerifySignature(SLHDSAPublicKeyParameters pubKey, byte[] msgPrefix, byte[] msg,
        byte[] signature)
    {
        // TODO Check init via pubKey != null
        
        //# Input: Message M, signature SIG, public key PK
        //# Output: Boolean

        // init
        SLHDSAEngine engine = pubKey.getParameters().getEngine();

        engine.init(pubKey.getSeed());

        ADRS adrs = new ADRS();

        if (((1 + engine.K * (1 + engine.A) + engine.H + engine.D * engine.WOTS_LEN) * engine.N) != signature.length)
        {
            return false;
        }

        SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);

        byte[] R = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] SIG_HT = sig.getSIG_HT();

        // compute message digest and index
        IndexedDigest idxDigest = engine.H_msg(R, pubKey.getSeed(), pubKey.getRoot(), msgPrefix, msg);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;

        // compute FORS public key
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = new Fors(engine).pkFromSig(sig_fors, mHash, pubKey.getSeed(), adrs);
        // verify HT signature
        adrs.setTypeAndClear(ADRS.TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        HT ht = new HT(engine, null, pubKey.getSeed());
        return ht.verify(PK_FORS, SIG_HT, pubKey.getSeed(), idx_tree, idx_leaf, pubKey.getRoot());
    }

    protected byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        return internalGenerateSignature(privKey, null, message, optRand);
    }

    private static byte[] internalGenerateSignature(SLHDSAPrivateKeyParameters privKey, byte[] msgPrefix, byte[] msg,
        byte[] optRand)
    {
        // TODO Check init via privKey != null
        
        SLHDSAEngine engine = privKey.getParameters().getEngine();
        engine.init(privKey.pk.seed);

        Fors fors = new Fors(engine);
        byte[] R = engine.PRF_msg(privKey.sk.prf, optRand, msgPrefix, msg);

        IndexedDigest idxDigest = engine.H_msg(R, privKey.pk.seed, privKey.pk.root, msgPrefix, msg);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;
        // FORS sign
        ADRS adrs = new ADRS();
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        SIG_FORS[] sig_fors = fors.sign(mHash, privKey.sk.seed, privKey.pk.seed, adrs);
        // get FORS public key - spec shows M?
        adrs = new ADRS();
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = fors.pkFromSig(sig_fors, mHash, privKey.pk.seed, adrs);

        // sign FORS public key with HT
        ADRS treeAdrs = new ADRS();
        treeAdrs.setTypeAndClear(ADRS.TREE);

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
}
