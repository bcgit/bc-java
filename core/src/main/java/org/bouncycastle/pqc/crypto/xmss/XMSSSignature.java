package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSS Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSSignature extends XMSSReducedSignature implements XMSSStoreableObjectInterface {

	/**
	 * Index of signature.
	 */
	private int index;
	
	/**
	 * Random used to create digest of message.
	 */
	private byte[] random;
	
	/**
	 * Constructor...
	 * @param signature The WOTS+ signature.
	 * @param authPath The authentication path.
	 */
	public XMSSSignature(XMSSParameters params) {
		super(params);
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		random = new byte[params.getDigestSize()];
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || signature || authentication path */
		int n = getParams().getDigestSize();
		int indexSize = 4;
		int randomSize = n;
		int signatureSize = getParams().getWOTSPlus().getParams().getLen() * n;
		int authPathSize = getParams().getHeight() * n;
		int totalSize = indexSize + randomSize + signatureSize + authPathSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		XMSSUtil.intToBytesBigEndianOffset(out, index, position);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, random, position);
		position += randomSize;
		/* copy signature */
		byte[][] signature = getSignature().toByteArray();
		for (int i = 0; i < signature.length; i++) {
			XMSSUtil.copyBytesAtOffset(out, signature[i], position);
			position += n;
		}
		/* copy authentication path */
		for (int i = 0; i < getAuthPath().size(); i++) {
			byte[] value = getAuthPath().get(i).getValue();
			XMSSUtil.copyBytesAtOffset(out, value, position);
			position += n;
		}
		return out;
	}

	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = getParams().getDigestSize();
		int len = getParams().getWOTSPlus().getParams().getLen();
		int height = getParams().getHeight();
		int indexSize = 4;
		int randomSize = n;
		int signatureSize = len * n;
		int authPathSize = height * n;
		int totalSize = indexSize + randomSize + signatureSize + authPathSize;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		index = XMSSUtil.bytesToIntBigEndian(in, position);
		if (!XMSSUtil.isIndexValid(height, index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		random = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
		position += randomSize;
		byte[][] wotsPlusSignature = new byte[len][];
		for (int i = 0; i < wotsPlusSignature.length; i++) {
			wotsPlusSignature[i] = XMSSUtil.extractBytesAtOffset(in, position, n);
			position += n;
		}
		WOTSPlusSignature wotsPlusSig = new WOTSPlusSignature(getParams().getWOTSPlus().getParams());
		wotsPlusSig.setSignature(wotsPlusSignature);
		setSignature(wotsPlusSig);
		
		List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
		for (int i = 0; i < height; i++) {
			nodeList.add(new XMSSNode(i, XMSSUtil.extractBytesAtOffset(in, position, n)));
			position += n;
		}
		setAuthPath(nodeList);
	}

	/**
	 * Getter index.
	 * @return index.
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Setter index.
	 * @param index
	 */
	public void setIndex(int index) {
		this.index = index;
	}

	/**
	 * Getter random.
	 * @return random.
	 */
	public byte[] getRandom() {
		return XMSSUtil.cloneArray(random);
	}

	/**
	 * Setter random.
	 * @param random random.
	 */
	public void setRandom(byte[] random) {
		if (random == null) {
			throw new NullPointerException("random == null");
		}
		if (random.length != getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of random needs to be equal to size of digest");
		}
		this.random = random;
	}
}
