package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.util.Arrays;

/**
 * The BDS traversal state stored with a private key carries two collections the next authentication
 * path reads from - the node kept when the path last passed a height, and the queue of retained
 * right nodes - and a state that reached its index by signing always has the entries the next step
 * will ask for. A state that arrived by import need not: the structural checks the encoding and
 * BDS.validate() make reject entries that are present and wrong, but say nothing about ones that
 * are simply absent, so the reads used to fall through into a NullPointerException from inside the
 * hash function, or a NoSuchElementException from the queue. Both now say what is wrong.
 */
public class CorruptedStateTests
    extends TestCase
{
    private static final int HEIGHT = 4;

    /**
     * The harness itself: taking a key apart and putting it back together unchanged has to leave a
     * key that still signs, or the corruption tests below would pass for the wrong reason. At both
     * of the indices they use, since what each of them removes is read at one of the two.
     */
    public void testUntouchedStateStillSigns()
        throws Exception
    {
        int[] indices = new int[]{1, 7};

        for (int i = 0; i != indices.length; i++)
        {
            XMSSPrivateKeyParameters privKey = importRebuilt(indices[i], null);

            assertEquals(indices[i], privKey.getIndex());

            XMSSSigner signer = new XMSSSigner();

            signer.init(true, privKey);
            signer.update((byte)9);
            signer.generateSignature();

            assertEquals(indices[i] + 1,
                ((XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey()).getIndex());
        }
    }

    /**
     * Index 1 is the first index whose next authentication path reads the kept node - tau is 1
     * there, so the step needs keep[0], put there by the step at index 0.
     */
    public void testMissingKeepNodeReported()
        throws Exception
    {
        checkReported(1, "keep", "missing keep node in BDS state");
    }

    /**
     * Index 7 is the first index whose next authentication path reaches into the retain queue - tau
     * is 3 there, and heights at or above treeHeight - k are served from retain rather than from a
     * tree hash instance.
     */
    public void testMissingRetainQueueReported()
        throws Exception
    {
        checkReported(7, "retain", "missing retain node in BDS state");
    }

    /**
     * A queue that is present but has nothing left in it: structurally valid, and the read used to
     * come back as a NoSuchElementException raised by the queue itself.
     */
    public void testEmptyRetainQueueReported()
        throws Exception
    {
        checkReported(7, "retain-empty", "missing retain node in BDS state");
    }

    /**
     * The state carries a checksum over itself bound to the owning key's public seed, and every
     * single-byte change past its eight-byte header is refused by it. The node values inside a BDS
     * state cannot be checked any other way - a path, stack, retain or keep node has no children
     * stored beside it, so recomputing one means rebuilding a subtree, which is the work the state
     * exists to avoid - so without this a corrupted state decodes and then signs, and the signature
     * simply does not verify.
     * <p>
     * The header is the other eight bytes: a change there is not recognised as a codec encoding at
     * all and falls through to the legacy Java-serialization reader, which refuses it for its own
     * reasons. Both halves are asserted, because a magic that stopped being checked would send a
     * valid codec encoding down that reader instead.
     * </p><p>
     * What this is not is integrity protection - anyone able to rewrite the stored key recomputes
     * it (github #2414).
     * </p>
     */
    public void testEveryCorruptionOfTheStateBodyIsRefusedByTheChecksum()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        byte[] encoded = signedTo(params, 3);
        int stateOffset = 4 + 4 * params.getTreeDigestSize();

        for (int i = stateOffset + 8; i != encoded.length; i++)
        {
            byte[] corrupt = Arrays.clone(encoded);

            corrupt[i] ^= 0x01;

            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("corrupt state byte " + i + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("byte " + i, "BDS state checksum does not match", e.getMessage());
            }
        }

        for (int i = stateOffset; i != stateOffset + 8; i++)
        {
            byte[] corrupt = Arrays.clone(encoded);

            corrupt[i] ^= 0x01;

            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("corrupt state header byte " + i + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                // refused by the magic and version check, or by the legacy reader it falls through
                // to - which is what the missing magic leaves behind
            }
        }

        // the harness: the encoding these were made from decodes and still signs, or every case
        // above would be passing for a reason of its own
        XMSSPrivateKeyParameters decoded =
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, decoded);
        signer.update((byte)9);
        assertNotNull(signer.generateSignature());
    }

    /**
     * A state that is internally consistent and brings its own matching root, taken off a different
     * key of the same parameters, is refused too: the checksum is taken with the owning key's public
     * seed in front of it, so it does not carry across keys. This is the case a checksum over the
     * state alone would accept, and the one that would put a key on a traversal state belonging to a
     * tree it does not describe.
     */
    public void testStateFromAnotherKeyIsRefused()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        byte[] mine = signedTo(params, 3);
        byte[] theirs = signedTo(params, 3);
        int stateOffset = 4 + 4 * params.getTreeDigestSize();

        assertEquals(mine.length, theirs.length);

        byte[] transplant = Arrays.clone(mine);

        System.arraycopy(theirs, stateOffset, transplant, stateOffset, theirs.length - stateOffset);

        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(transplant).build();
            fail("state from a different key accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS state checksum does not match", e.getMessage());
        }
    }

    /**
     * A fresh key advanced by {@code signatures} signatures, encoded.
     */
    private byte[] signedTo(XMSSParameters params, int signatures)
        throws Exception
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kpg.generateKeyPair().getPrivate());

        for (int i = 0; i != signatures; i++)
        {
            signer.update((byte)i);
            signer.generateSignature();
        }

        return ((XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey()).getEncoded();
    }

    private void checkReported(int atIndex, String drop, String expected)
        throws Exception
    {
        XMSSPrivateKeyParameters privKey = importRebuilt(atIndex, drop);
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);
        signer.update((byte)9);

        try
        {
            signer.generateSignature();
            fail("corrupt state signed: " + drop);
        }
        catch (IllegalStateException e)
        {
            assertEquals(expected, e.getMessage());
        }
    }

    /**
     * A private key advanced to {@code atIndex}, re-encoded with the named part of its BDS state
     * removed, and imported again through the ordinary encoded-key path.
     */
    private XMSSPrivateKeyParameters importRebuilt(int atIndex, String drop)
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        for (int i = 0; i != atIndex; i++)
        {
            signer.update((byte)i);
            signer.generateSignature();
        }

        byte[] encoded = ((XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey()).getEncoded();
        int n = params.getTreeDigestSize();
        int prefix = 4 + 4 * n;
        byte[] head = Arrays.copyOfRange(encoded, 0, prefix);
        // head is index(4) || secretKeySeed(n) || secretKeyPRF(n) || publicSeed(n) || root(n)
        byte[] publicSeed = Arrays.copyOfRange(head, 4 + 2 * n, 4 + 3 * n);
        BDS state = BDSStateCodec.decodeBDS(Arrays.copyOfRange(encoded, prefix, encoded.length), publicSeed);

        assertEquals(atIndex, state.getIndex());

        // these are the state's own collections rather than copies of them, so each corruption
        // replaces one and none of them changes one in place. The BDS constructor below adopts
        // what it is handed, so the rebuilt state shares the uncorrupted four with the state read
        // from the encoding - which is why that state is not touched again: it is encoded through
        // the rebuilt one on the next line and then dropped.
        Map<Integer, XMSSNode> keep = state.getLiveKeep();
        Map<Integer, List<XMSSNode>> retain = state.getLiveRetain();

        if ("keep".equals(drop))
        {
            assertFalse("nothing kept at index " + atIndex, keep.isEmpty());
            keep = new TreeMap<Integer, XMSSNode>();
        }
        else if ("retain".equals(drop))
        {
            assertFalse("nothing retained at index " + atIndex, retain.isEmpty());
            retain = new TreeMap<Integer, List<XMSSNode>>();
        }
        else if ("retain-empty".equals(drop))
        {
            Map<Integer, List<XMSSNode>> emptied = new TreeMap<Integer, List<XMSSNode>>();

            for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
            {
                emptied.put(it.next(), new LinkedList<XMSSNode>());
            }

            assertFalse("nothing retained at index " + atIndex, emptied.isEmpty());
            retain = emptied;
        }
        else if (drop != null)
        {
            fail("unknown corruption: " + drop);
        }

        BDS rebuilt = new BDS(state.getTreeHeight(), state.getK(), state.getMaxIndex(), state.getIndex(),
            state.isUsed(), state.getRoot(), state.getLiveAuthenticationPath(), retain,
            state.getLiveStack(), state.getLiveTreeHashInstances(), keep);

        return new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(Arrays.concatenate(head, BDSStateCodec.encode(rebuilt, publicSeed))).build();
    }
}
