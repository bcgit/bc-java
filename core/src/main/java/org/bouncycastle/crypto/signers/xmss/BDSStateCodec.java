package org.bouncycastle.crypto.signers.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Codec for the implementation-specific BDS traversal state stored with an XMSS or XMSSMT private key.
 * <p>
 * RFC 8391 Sections 4.1.7 and 4.2.2 leave the private-key representation unspecified, and Section 4.1.9
 * refers to BDS [BDS09] only as one of the authentication-path computation optimizations. Consequently,
 * this versioned encoding is a BC private-key implementation detail, not an RFC-defined interchange format.
 * </p>
 */
final class BDSStateCodec
{
    public static final int BDS_STATE_MAGIC = 0x42445300;
    public static final int BDS_STATE_MAP_MAGIC = 0x42444d00;

    private static final int STATE_VERSION = 1;
    private static final int MAX_ENCODED_STATE_SIZE = 4 * 1024 * 1024;
    private static final int MAX_DIGEST_SIZE = 64;
    private static final int MAX_STATE_MAP_ENTRIES = 64;
    private static final int MAX_NODES = 4096;
    private static final int CHECKSUM_SIZE = 32;

    /**
     * The bytes withChecksum() reserves at the end of the stream before copying the encoding out of
     * it, overwritten with the checksum itself the moment it has. Only ever read from, so sharing it
     * says nothing about threads.
     */
    private static final byte[] CHECKSUM_PLACEHOLDER = new byte[CHECKSUM_SIZE];

    private BDSStateCodec()
    {
    }

    public static boolean isBDSStateEncoding(byte[] encoding)
    {
        return hasMagic(encoding, BDS_STATE_MAGIC);
    }

    public static boolean isBDSStateMapEncoding(byte[] encoding)
    {
        return hasMagic(encoding, BDS_STATE_MAP_MAGIC);
    }

    public static byte[] encode(BDS state, byte[] publicSeed)
        throws IOException
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(byteOut);
        dataOut.writeInt(BDS_STATE_MAGIC);
        dataOut.writeInt(STATE_VERSION);
        writeBDS(dataOut, state);
        dataOut.flush();
        return checkedEncoding(withChecksum(byteOut, publicSeed));
    }

    public static byte[] encode(BDSStateMap stateMap, byte[] publicSeed)
        throws IOException
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(byteOut);
        dataOut.writeInt(BDS_STATE_MAP_MAGIC);
        dataOut.writeInt(STATE_VERSION);
        dataOut.writeLong(stateMap.getMaxIndex());

        Map<Integer, BDS> states = stateMap.getStateMap();
        if (states.size() > MAX_STATE_MAP_ENTRIES)
        {
            throw new IOException("too many BDS states");
        }
        dataOut.writeInt(states.size());
        for (Iterator<Integer> it = states.keySet().iterator(); it.hasNext();)
        {
            Integer layer = it.next();
            dataOut.writeInt(layer.intValue());
            writeBDS(dataOut, states.get(layer));
        }
        dataOut.flush();
        return checkedEncoding(withChecksum(byteOut, publicSeed));
    }

    public static BDS decodeBDS(byte[] encoding, byte[] publicSeed)
        throws IOException
    {
        checkEncodingSize(encoding);
        DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(
            encoding, 0, checkedBodyLength(encoding, publicSeed)));
        readHeader(dataIn, BDS_STATE_MAGIC);
        BDS state = readBDS(dataIn, new NodeBudget());
        checkFinished(dataIn);
        return state;
    }

    public static BDSStateMap decodeBDSStateMap(byte[] encoding, byte[] publicSeed)
        throws IOException
    {
        checkEncodingSize(encoding);
        DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(
            encoding, 0, checkedBodyLength(encoding, publicSeed)));
        readHeader(dataIn, BDS_STATE_MAP_MAGIC);

        long maxIndex = dataIn.readLong();
        if (maxIndex < 0)
        {
            throw new IOException("negative BDS state map maxIndex");
        }
        int stateCount = readCount(dataIn, MAX_STATE_MAP_ENTRIES, "BDS state map");
        BDSStateMap stateMap = new BDSStateMap(maxIndex);
        NodeBudget nodeBudget = new NodeBudget();
        int previousLayer = -1;
        for (int i = 0; i < stateCount; i++)
        {
            int layer = dataIn.readInt();
            if (layer <= previousLayer)
            {
                throw new IOException("invalid BDS state map layer");
            }
            stateMap.put(layer, readBDS(dataIn, nodeBudget));
            previousLayer = layer;
        }
        checkFinished(dataIn);
        return stateMap;
    }

    private static void writeBDS(DataOutputStream dataOut, BDS state)
        throws IOException
    {
        try
        {
            state.validate();
        }
        catch (IllegalStateException e)
        {
            throw invalidState(e);
        }

        int treeHeight = state.getTreeHeight();
        dataOut.writeInt(treeHeight);
        dataOut.writeInt(state.getK());
        dataOut.writeInt(state.getMaxIndex());
        dataOut.writeInt(state.getIndex());
        writeBoolean(dataOut, state.isUsed());
        writeOptionalNode(dataOut, state.getRoot(), treeHeight);

        List<XMSSNode> authenticationPath = state.getLiveAuthenticationPath();
        dataOut.writeInt(authenticationPath.size());
        for (int i = 0; i < authenticationPath.size(); i++)
        {
            writeNode(dataOut, authenticationPath.get(i), treeHeight);
        }

        Map<Integer, List<XMSSNode>> retain = state.getLiveRetain();
        dataOut.writeInt(retain.size());
        for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();
            List<XMSSNode> nodes = retain.get(height);
            dataOut.writeInt(height.intValue());
            dataOut.writeInt(nodes.size());
            writeNodes(dataOut, nodes, treeHeight);
        }

        Stack<XMSSNode> stack = state.getLiveStack();
        dataOut.writeInt(stack.size());
        writeNodes(dataOut, stack, treeHeight);

        List<BDSTreeHash> treeHashes = state.getLiveTreeHashInstances();
        dataOut.writeInt(treeHashes.size());
        for (Iterator<BDSTreeHash> it = treeHashes.iterator(); it.hasNext();)
        {
            BDSTreeHash treeHash = it.next();
            dataOut.writeInt(treeHash.getInitialHeight());
            dataOut.writeInt(treeHash.getRawHeight());
            dataOut.writeInt(treeHash.getIndexLeaf());
            writeBoolean(dataOut, treeHash.isInitialized());
            writeBoolean(dataOut, treeHash.isFinished());
            writeOptionalNode(dataOut, treeHash.getTailNode(), treeHeight);
        }

        Map<Integer, XMSSNode> keep = state.getLiveKeep();
        dataOut.writeInt(keep.size());
        for (Iterator<Integer> it = keep.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();
            dataOut.writeInt(height.intValue());
            writeNode(dataOut, keep.get(height), treeHeight);
        }
    }

    private static BDS readBDS(DataInputStream dataIn, NodeBudget nodeBudget)
        throws IOException
    {
        int treeHeight = dataIn.readInt();
        int k = dataIn.readInt();
        int maxIndex = dataIn.readInt();
        int index = dataIn.readInt();
        boolean used = readBoolean(dataIn);

        if (treeHeight < 2 || treeHeight > XMSSParameters.MAX_HEIGHT)
        {
            throw new IOException("BDS tree height out of bounds");
        }
        // k controls the BDS time-memory trade-off; it is not an XMSS wire parameter. The BDS traversal
        // layout requires 2 <= k <= treeHeight and an even treeHeight - k.
        if (k < 2 || k > treeHeight || ((treeHeight - k) & 1) != 0)
        {
            throw new IOException("BDS k out of bounds");
        }
        int maxIndexLimit = (1 << treeHeight) - 1;
        if (maxIndex < 0 || maxIndex > maxIndexLimit || index < 0 || index > maxIndex + 1)
        {
            throw new IOException("BDS index out of bounds");
        }

        XMSSNode root = readOptionalNode(dataIn, treeHeight, nodeBudget);
        if (root != null && root.getHeight() != treeHeight)
        {
            throw new IOException("BDS root has wrong height");
        }

        int authenticationPathCount = readCount(dataIn, treeHeight, "BDS authentication path");
        if (authenticationPathCount != 0 && authenticationPathCount != treeHeight)
        {
            throw new IOException("BDS authentication path has wrong size");
        }
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>(authenticationPathCount);
        for (int i = 0; i < authenticationPathCount; i++)
        {
            authenticationPath.add(readNode(dataIn, i, i, nodeBudget));
        }
        if ((root == null) != authenticationPath.isEmpty())
        {
            throw new IOException("inconsistent BDS root and authentication path");
        }

        int retainCount = readCount(dataIn, k - 1, "BDS retain map");
        Map<Integer, List<XMSSNode>> retain = new TreeMap<Integer, List<XMSSNode>>();
        int previousRetainHeight = treeHeight - k - 1;
        for (int i = 0; i < retainCount; i++)
        {
            int height = dataIn.readInt();
            if (height <= previousRetainHeight || height > treeHeight - 2)
            {
                throw new IOException("invalid BDS retain height");
            }
            int maximumRetained = (1 << (treeHeight - height - 1)) - 1;
            int nodeCount = readCount(dataIn, Math.min(maximumRetained, nodeBudget.remaining()),
                "BDS retain queue");
            LinkedList<XMSSNode> nodes = new LinkedList<XMSSNode>();
            for (int j = 0; j < nodeCount; j++)
            {
                nodes.add(readNode(dataIn, height, height, nodeBudget));
            }
            retain.put(Integers.valueOf(height), nodes);
            previousRetainHeight = height;
        }

        int stackCount = readCount(dataIn, Math.min(treeHeight, nodeBudget.remaining()), "BDS stack");
        Stack<XMSSNode> stack = new Stack<XMSSNode>();
        for (int i = 0; i < stackCount; i++)
        {
            stack.push(readNode(dataIn, 0, treeHeight, nodeBudget));
        }
        int expectedTreeHashCount = treeHeight - k;
        int treeHashCount = readCount(dataIn, expectedTreeHashCount, "BDS tree hash");
        if (treeHashCount != expectedTreeHashCount)
        {
            throw new IOException("BDS tree hash has wrong size");
        }
        List<BDSTreeHash> treeHashes = new ArrayList<BDSTreeHash>(treeHashCount);
        for (int i = 0; i < treeHashCount; i++)
        {
            int initialHeight = dataIn.readInt();
            int height = dataIn.readInt();
            int nextIndex = dataIn.readInt();
            boolean initialized = readBoolean(dataIn);
            boolean finished = readBoolean(dataIn);
            if (initialHeight != i || height < 0 || height > initialHeight
                || nextIndex < 0 || nextIndex > maxIndexLimit)
            {
                throw new IOException("invalid BDS tree hash state");
            }
            XMSSNode tailNode = readOptionalNode(dataIn, treeHeight, nodeBudget);
            if (tailNode != null && tailNode.getHeight() > initialHeight)
            {
                throw new IOException("BDS tree hash tail has wrong height");
            }
            treeHashes.add(new BDSTreeHash(initialHeight, height, nextIndex, initialized, finished, tailNode));
        }

        int keepCount = readCount(dataIn, Math.min(treeHeight, nodeBudget.remaining()), "BDS keep map");
        Map<Integer, XMSSNode> keep = new TreeMap<Integer, XMSSNode>();
        int previousKeepHeight = -1;
        for (int i = 0; i < keepCount; i++)
        {
            int height = dataIn.readInt();
            if (height <= previousKeepHeight || height > treeHeight - 2)
            {
                throw new IOException("invalid BDS keep height");
            }
            keep.put(Integers.valueOf(height), readNode(dataIn, height, height, nodeBudget));
            previousKeepHeight = height;
        }

        try
        {
            return new BDS(treeHeight, k, maxIndex, index, used, root, authenticationPath, retain, stack,
                treeHashes, keep);
        }
        catch (IllegalStateException e)
        {
            throw invalidState(e);
        }
    }

    private static void writeNodes(DataOutputStream dataOut, Iterable<XMSSNode> nodes, int treeHeight)
        throws IOException
    {
        for (Iterator<XMSSNode> it = nodes.iterator(); it.hasNext();)
        {
            writeNode(dataOut, it.next(), treeHeight);
        }
    }

    private static void writeOptionalNode(DataOutputStream dataOut, XMSSNode node, int treeHeight)
        throws IOException
    {
        writeBoolean(dataOut, node != null);
        if (node != null)
        {
            writeNode(dataOut, node, treeHeight);
        }
    }

    private static void writeNode(DataOutputStream dataOut, XMSSNode node, int treeHeight)
        throws IOException
    {
        if (node == null)
        {
            throw new IOException("null XMSS node");
        }
        int valueLength = node.getValueLength();
        if (node.getHeight() < 0 || node.getHeight() > treeHeight
            || valueLength < 1 || valueLength > MAX_DIGEST_SIZE)
        {
            throw new IOException("XMSS node out of bounds");
        }
        dataOut.writeInt(node.getHeight());
        dataOut.writeInt(valueLength);
        node.encodeTo(dataOut);
    }

    private static XMSSNode readOptionalNode(DataInputStream dataIn, int treeHeight, NodeBudget nodeBudget)
        throws IOException
    {
        if (!readBoolean(dataIn))
        {
            return null;
        }
        return readNode(dataIn, 0, treeHeight, nodeBudget);
    }

    private static XMSSNode readNode(DataInputStream dataIn, int minimumHeight, int maximumHeight,
        NodeBudget nodeBudget)
        throws IOException
    {
        nodeBudget.consume();
        int height = dataIn.readInt();
        int valueSize = dataIn.readInt();
        if (height < minimumHeight || height > maximumHeight)
        {
            throw new IOException("XMSS node height out of bounds");
        }
        if (valueSize < 1 || valueSize > MAX_DIGEST_SIZE)
        {
            throw new IOException("XMSS node value size out of bounds");
        }
        nodeBudget.setDigestSize(valueSize);
        byte[] value = new byte[valueSize];
        dataIn.readFully(value);
        return new XMSSNode(height, value);
    }

    /**
     * The trailing checksum over the encoded state, with the key's public seed hashed in front of it.
     * <p>
     * <b>This is an error-detecting code, not integrity protection.</b> Anyone able to rewrite the
     * stored private key can recompute it, so it authenticates nothing; what it catches is accidental
     * corruption - bit rot, a partial write, a truncated record - of the node values inside the state,
     * which cannot be checked any other way. A BDS authentication path, stack, retain or keep node does
     * not have its children stored beside it, so recomputing one means rebuilding a subtree, which is
     * the work this state exists to avoid. It therefore only establishes that the state is unchanged
     * since it was written, never that it was right when written.
     * <p>
     * The public seed is hashed in because the state's own root and index are inside the encoding and so
     * are already covered: binding the seed as well ties the state to the key it belongs to, so a state
     * transplanted between two keys of the same parameters fails here even though it is internally
     * consistent. The seed is a public value, deliberately - hashing the secret seed or the PRF key
     * instead would make the stored checksum a commitment to secret material for no gain in detection,
     * and the PRF key does not influence the state at all.
     * <p>
     * The digest is SHA-256 whatever the parameter set's tree digest is: this is a checksum over an
     * implementation-detail encoding, not part of any scheme.
     *
     * @param publicSeed the key's public seed, or null to bind nothing.
     */
    private static void checksumTo(byte[] encoding, int length, byte[] publicSeed, byte[] out, int outOff)
    {
        Digest digest = new SHA256Digest(CryptoServicePurpose.INTERNAL);

        if (publicSeed != null)
        {
            digest.update(publicSeed, 0, publicSeed.length);
        }
        digest.update(encoding, 0, length);

        digest.doFinal(out, outOff);
    }

    /**
     * The encoding held by {@code byteOut}, with its checksum appended.
     * <p>
     * The stream's own bytes are the body, so the checksum's room is reserved in the stream before
     * the one copy that takes the encoding out of it, and the checksum is then written straight into
     * the tail of that copy. Appending it afterwards with Arrays.concatenate meant a second copy of
     * the whole body - which for a private key encoding is the bulk of it, and the encode path
     * copies it once more on the way into the key.
     */
    private static byte[] withChecksum(ByteArrayOutputStream byteOut, byte[] publicSeed)
    {
        int bodyLength = byteOut.size();
        byteOut.write(CHECKSUM_PLACEHOLDER, 0, CHECKSUM_SIZE);

        byte[] encoding = byteOut.toByteArray();
        checksumTo(encoding, bodyLength, publicSeed, encoding, bodyLength);

        return encoding;
    }

    /**
     * Verify the trailing checksum and return the length of the body it covers, so the caller can read
     * the body in place rather than copying it out.
     */
    private static int checkedBodyLength(byte[] encoding, byte[] publicSeed)
        throws IOException
    {
        if (encoding.length < CHECKSUM_SIZE + 8)
        {
            throw new IOException("BDS state encoding size out of bounds");
        }

        int bodyLength = encoding.length - CHECKSUM_SIZE;
        byte[] expected = new byte[CHECKSUM_SIZE];
        checksumTo(encoding, bodyLength, publicSeed, expected, 0);

        // an error-detecting checksum over material that is not secret, so a plain comparison is
        // what is wanted here - see the note on checksum()
        if (!Arrays.areEqual(expected, 0, CHECKSUM_SIZE, encoding, bodyLength, encoding.length))
        {
            throw new IOException("BDS state checksum does not match");
        }

        return bodyLength;
    }

    private static void readHeader(DataInputStream dataIn, int expectedMagic)
        throws IOException
    {
        if (dataIn.readInt() != expectedMagic)
        {
            throw new IOException("unexpected BDS state magic");
        }
        if (dataIn.readInt() != STATE_VERSION)
        {
            throw new IOException("unsupported BDS state version");
        }
    }

    private static boolean readBoolean(DataInputStream dataIn)
        throws IOException
    {
        int value = dataIn.readUnsignedByte();
        if (value > 1)
        {
            throw new IOException("invalid boolean in BDS state");
        }
        return value == 1;
    }

    private static void writeBoolean(DataOutputStream dataOut, boolean value)
        throws IOException
    {
        dataOut.writeByte(value ? 1 : 0);
    }

    private static int readCount(DataInputStream dataIn, int maximum, String name)
        throws IOException
    {
        int count = dataIn.readInt();
        if (count < 0 || count > maximum)
        {
            throw new IOException(name + " size out of bounds");
        }
        return count;
    }

    private static void checkFinished(DataInputStream dataIn)
        throws IOException
    {
        if (dataIn.available() != 0)
        {
            throw new IOException("unexpected data at end of BDS state");
        }
    }

    private static byte[] checkedEncoding(byte[] encoding)
        throws IOException
    {
        checkEncodingSize(encoding);
        return encoding;
    }

    public static void checkEncodingSize(byte[] encoding)
        throws IOException
    {
        if (encoding == null || encoding.length < 8 || encoding.length > MAX_ENCODED_STATE_SIZE)
        {
            throw new IOException("BDS state encoding size out of bounds");
        }
    }

    private static boolean hasMagic(byte[] encoding, int magic)
    {
        return encoding != null && encoding.length >= 4 && Pack.bigEndianToInt(encoding, 0) == magic;
    }

    private static IOException invalidState(IllegalStateException cause)
    {
        return Exceptions.ioException("invalid BDS state", cause);
    }

    private static final class NodeBudget
    {
        private int remaining = MAX_NODES;
        private int digestSize;

        int remaining()
        {
            return remaining;
        }

        void consume()
            throws IOException
        {
            if (remaining == 0)
            {
                throw new IOException("too many XMSS nodes in BDS state");
            }
            remaining--;
        }

        void setDigestSize(int valueSize)
            throws IOException
        {
            if (digestSize == 0)
            {
                digestSize = valueSize;
            }
            else if (digestSize != valueSize)
            {
                throw new IOException("inconsistent XMSS node value sizes");
            }
        }
    }
}
