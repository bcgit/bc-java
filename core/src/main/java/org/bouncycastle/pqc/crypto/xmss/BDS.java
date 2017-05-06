package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

/**
 * BDS.
 *
 */
public final class BDS implements Serializable {

	private static final long serialVersionUID = 1L;

	private final class TreeHash implements Serializable {

		private static final long serialVersionUID = 1L;

		private XMSSNode tailNode;
		private final int initialHeight;
		private int height;
		private int nextIndex;
		private boolean initialized;
		private boolean finished;

		private TreeHash(int initialHeight) {
			super();
			this.initialHeight = initialHeight;
			initialized = false;
			finished = false;
		}

		private void initialize(int nextIndex) {
			tailNode = null;
			height = initialHeight;
			this.nextIndex = nextIndex;
			initialized = true;
			finished = false;
		}

		private void update(OTSHashAddress otsHashAddress) {
			if (otsHashAddress == null) {
				throw new NullPointerException("otsHashAddress == null");
			}
			if (finished || !initialized) {
				throw new IllegalStateException("finished or not initialized");
			}
			/* prepare addresses */
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
					.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
					.withOTSAddress(nextIndex).withChainAddress(otsHashAddress.getChainAddress())
					.withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
					.build();
			LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
					.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
					.withLTreeAddress(nextIndex).build();
			HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
					.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
					.withTreeIndex(nextIndex).build();

			/* calculate leaf node */
			wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
			WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
			XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);

			while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()
					&& stack.peek().getHeight() != initialHeight) {
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight())
						.withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
						.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				node = xmss.randomizeHash(stack.pop(), node, hashTreeAddress);
				node = new XMSSNode(node.getHeight() + 1, node.getValue());
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
						.withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())
						.build();
			}

			if (tailNode == null) {
				tailNode = node;
			} else {
				if (tailNode.getHeight() == node.getHeight()) {
					hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
							.withLayerAddress(hashTreeAddress.getLayerAddress())
							.withTreeAddress(hashTreeAddress.getTreeAddress())
							.withTreeHeight(hashTreeAddress.getTreeHeight())
							.withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
							.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
					node = xmss.randomizeHash(tailNode, node, hashTreeAddress);
					node = new XMSSNode(tailNode.getHeight() + 1, node.getValue());
					tailNode = node;
					hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
							.withLayerAddress(hashTreeAddress.getLayerAddress())
							.withTreeAddress(hashTreeAddress.getTreeAddress())
							.withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
							.withTreeIndex(hashTreeAddress.getTreeIndex())
							.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				} else {
					stack.push(node);
				}
			}

			if (tailNode.getHeight() == initialHeight) {
				finished = true;
			} else {
				height = node.getHeight();
				nextIndex++;
			}
		}

		private int getHeight() {
			if (!initialized || finished) {
				return Integer.MAX_VALUE;
			}
			return height;
		}

		private int getIndexLeaf() {
			return nextIndex;
		}

		private void setNode(XMSSNode node) {
			tailNode = node;
			height = node.getHeight();
			if (height == initialHeight) {
				finished = true;
			}
		}

		private boolean isFinished() {
			return finished;
		}

		private boolean isInitialized() {
			return initialized;
		}
	}

	private transient XMSS xmss;
	private transient WOTSPlus wotsPlus;
	private final int treeHeight;
	private int k;
	private XMSSNode root;
	private List<XMSSNode> authenticationPath;
	private Map<Integer, LinkedList<XMSSNode>> retain;
	private Stack<XMSSNode> stack;
	private List<TreeHash> treeHashInstances;
	private Map<Integer, XMSSNode> keep;
	private int index;

	protected BDS(XMSS xmss) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		this.xmss = xmss;
		wotsPlus = xmss.getWOTSPlus();
		treeHeight = xmss.getParams().getHeight();
		k = xmss.getParams().getK();
		if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0) {
			throw new IllegalArgumentException("illegal value for BDS parameter k");
		}
		authenticationPath = new ArrayList<XMSSNode>();
		retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
		stack = new Stack<XMSSNode>();
		initializeTreeHashInstances();
		keep = new TreeMap<Integer, XMSSNode>();
		index = 0;
	}

	private void initializeTreeHashInstances() {
		treeHashInstances = new ArrayList<TreeHash>();
		for (int height = 0; height < (treeHeight - k); height++) {
			treeHashInstances.add(new TreeHash(height));
		}
	}

	protected XMSSNode initialize(OTSHashAddress otsHashAddress) {
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		/* prepare addresses */
		LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.build();
		HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.build();

		/* iterate indexes */
		for (int indexLeaf = 0; indexLeaf < (1 << treeHeight); indexLeaf++) {
			/* generate leaf */
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
					.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
					.withOTSAddress(indexLeaf).withChainAddress(otsHashAddress.getChainAddress())
					.withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
					.build();
			/*
			 * import WOTSPlusSecretKey as its needed to calculate the public
			 * key on the fly
			 */
			wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
			WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
			lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())
					.withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(indexLeaf)
					.withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex())
					.withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
			XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);

			hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
					.withLayerAddress(hashTreeAddress.getLayerAddress())
					.withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(indexLeaf)
					.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
			while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
				/* add to authenticationPath if leafIndex == 1 */
				int indexOnHeight = ((int) Math.floor(indexLeaf / (1 << node.getHeight())));
				if (indexOnHeight == 1) {
					authenticationPath.add(node.clone());
				}
				/* store next right authentication node */
				if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k)) {
					treeHashInstances.get(node.getHeight()).setNode(node.clone());
				}
				if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k)
						&& node.getHeight() <= (treeHeight - 2)) {
					if (retain.get(node.getHeight()) == null) {
						LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
						queue.add(node.clone());
						retain.put(node.getHeight(), queue);
					} else {
						retain.get(node.getHeight()).add(node.clone());
					}
				}
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight())
						.withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
						.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				node = xmss.randomizeHash(stack.pop(), node, hashTreeAddress);
				node = new XMSSNode(node.getHeight() + 1, node.getValue());
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
						.withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())
						.build();
			}
			/* push to stack */
			stack.push(node);
		}
		root = stack.pop();
		return root.clone();
	}

	protected void nextAuthenticationPath(OTSHashAddress otsHashAddress) {
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (index > ((1 << treeHeight) - 2)) {
			throw new IllegalStateException("index out of bounds");
		}
		/* prepare addresses */
		LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.build();
		HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.build();

		/* determine tau */
		int tau = XMSSUtil.calculateTau(index, treeHeight);

		/* parent of leaf on height tau+1 is a left node */
		if (((index >> (tau + 1)) & 1) == 0 && (tau < (treeHeight - 1))) {
			keep.put(tau, authenticationPath.get(tau).clone());
		}
		/* leaf is a left node */
		if (tau == 0) {
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
					.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
					.withOTSAddress(index).withChainAddress(otsHashAddress.getChainAddress())
					.withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
					.build();
			/*
			 * import WOTSPlusSecretKey as its needed to calculate the public
			 * key on the fly
			 */
			wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(otsHashAddress), xmss.getPublicSeed());
			WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
			lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())
					.withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(index)
					.withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex())
					.withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
			XMSSNode node = xmss.lTree(wotsPlusPublicKey, lTreeAddress);
			authenticationPath.set(0, node);
		} else {
			/* add new left node on height tau to authentication path */
			hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
					.withLayerAddress(hashTreeAddress.getLayerAddress())
					.withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(tau - 1)
					.withTreeIndex(index >> tau).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
			XMSSNode node = xmss.randomizeHash(authenticationPath.get(tau - 1), keep.get(tau - 1), hashTreeAddress);
			node = new XMSSNode(node.getHeight() + 1, node.getValue());
			authenticationPath.set(tau, node);
			keep.remove(tau - 1);

			/* add new right nodes to authentication path */
			for (int height = 0; height < tau; height++) {
				if (height < (treeHeight - k)) {
					authenticationPath.set(height, treeHashInstances.get(height).tailNode.clone());
				} else {
					authenticationPath.set(height, retain.get(height).removeFirst());
				}
			}

			/* reinitialize treehash instances */
			int minHeight = Math.min(tau, treeHeight - k);
			for (int height = 0; height < minHeight; height++) {
				int startIndex = index + 1 + (3 * (1 << height));
				if (startIndex < (1 << treeHeight)) {
					treeHashInstances.get(height).initialize(startIndex);
				}
			}
		}

		/* update treehash instances */
		for (int i = 0; i < (treeHeight - k) >> 1; i++) {
			TreeHash treeHash = getTreeHashInstanceForUpdate();
			if (treeHash != null) {
				treeHash.update(otsHashAddress);
			}
		}
		index++;
	}

	private TreeHash getTreeHashInstanceForUpdate() {
		TreeHash ret = null;
		for (TreeHash treeHash : treeHashInstances) {
			if (treeHash.isFinished() || !treeHash.isInitialized()) {
				continue;
			}
			if (ret == null) {
				ret = treeHash;
				continue;
			}
			if (treeHash.getHeight() < ret.getHeight()) {
				ret = treeHash;
				continue;
			}
			if (treeHash.getHeight() == ret.getHeight()) {
				if (treeHash.getIndexLeaf() < ret.getIndexLeaf()) {
					ret = treeHash;
				}
			}
		}
		return ret;
	}

	protected void validate() {
		if (treeHeight != xmss.getParams().getHeight()) {
			throw new IllegalStateException("wrong height");
		}
		if (authenticationPath == null) {
			throw new IllegalStateException("authenticationPath == null");
		}
		if (retain == null) {
			throw new IllegalStateException("retain == null");
		}
		if (stack == null) {
			throw new IllegalStateException("stack == null");
		}
		if (treeHashInstances == null) {
			throw new IllegalStateException("treeHashInstances == null");
		}
		if (keep == null) {
			throw new IllegalStateException("keep == null");
		}
		if (!XMSSUtil.isIndexValid(treeHeight, index)) {
			throw new IllegalStateException("index in BDS state out of bounds");
		}
	}

	protected int getTreeHeight() {
		return treeHeight;
	}

	protected XMSSNode getRoot() {
		return root.clone();
	}

	protected List<XMSSNode> getAuthenticationPath() {
		List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();
		for (XMSSNode node : this.authenticationPath) {
			authenticationPath.add(node.clone());
		}
		return authenticationPath;
	}

	protected void setXMSS(XMSS xmss) {
		this.xmss = xmss;
		this.wotsPlus = xmss.getWOTSPlus();
	}

	protected int getIndex() {
		return index;
	}
}
