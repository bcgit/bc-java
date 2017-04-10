package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Reduced XMSS Signature for MT variant.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSReducedSignature implements XMSSStoreableObjectInterface {
	
	/**
	 * XMSS object.
	 */
	private XMSSParameters params;
	/**
	 * WOTS+ signature.
	 */
	private WOTSPlusSignature signature;
	/**
	 * Authentication path.
	 */
	private List<XMSSNode> authPath;
	
	/**
	 * Constructor...
	 * @param signature The WOTS+ signature.
	 * @param authPath The authentication path.
	 */
	public XMSSReducedSignature(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		signature = new WOTSPlusSignature(params.getWOTSPlus().getParams());
		authPath = new ArrayList<XMSSNode>();
	}

	@Override
	public byte[] toByteArray() {
		/* signature || authentication path */
		int n = params.getDigestSize();
		int signatureSize = params.getWOTSPlus().getParams().getLen() * n;
		int authPathSize = params.getHeight() * n;
		int totalSize = signatureSize + authPathSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy signature */
		byte[][] signature = this.signature.toByteArray();
		for (int i = 0; i < signature.length; i++) {
			XMSSUtil.copyBytesAtOffset(out, signature[i], position);
			position += n;
		}
		/* copy authentication path */
		for (int i = 0; i < authPath.size(); i++) {
			byte[] value = authPath.get(i).getValue();
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
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int height = params.getHeight();
		int signatureSize = len * n;
		int authPathSize = height * n;
		int totalSize = signatureSize + authPathSize;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		byte[][] wotsPlusSignature = new byte[len][];
		for (int i = 0; i < wotsPlusSignature.length; i++) {
			wotsPlusSignature[i] = XMSSUtil.extractBytesAtOffset(in, position, n);
			position += n;
		}
		signature = new WOTSPlusSignature(params.getWOTSPlus().getParams());
		signature.setSignature(wotsPlusSignature);
		
		List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
		for (int i = 0; i < height; i++) {
			nodeList.add(new XMSSNode(i, XMSSUtil.extractBytesAtOffset(in, position, n)));
			position += n;
		}
		authPath = nodeList;
	}

	/**
	 * Getter params.
	 * @return XMSS Parameters.
	 */
	protected XMSSParameters getParams() {
		return params;
	}

	/**
	 * Getter signature.
	 * @return WOTS+ signature.
	 */
	public WOTSPlusSignature getSignature() {
		return signature;
	}
	
	/**
	 * Setter WOTS+ signature
	 * @param signature WOTS+ signature.
	 */
	public void setSignature(WOTSPlusSignature signature) {
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		this.signature = signature;
	}

	/**
	 * Getter authentication path.
	 * @return Authentication path.
	 */
	public List<XMSSNode> getAuthPath() {
		return authPath;
	}
	
	/**
	 * Setter authentication path.
	 * @param authPath Authentication path.
	 */
	public void setAuthPath(List<XMSSNode> authPath) {
		if (authPath == null) {
			throw new NullPointerException("authPath == null");
		}
		if (authPath.size() != params.getHeight()) {
			throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
		}
		this.authPath = authPath;
	}
}
