package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSSMT Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTSignature implements XMSSStoreableObjectInterface {
	
	private XMSSMTParameters params;
	private long index;
	private byte[] random;
	private List<XMSSReducedSignature> reducedSignatures;
	
	public XMSSMTSignature(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		random = new byte[params.getDigestSize()];
		reducedSignatures = new ArrayList<XMSSReducedSignature>();
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || reduced signatures */
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int indexSize = (int)Math.ceil(params.getHeight() / (double) 8);
		int randomSize = n;
		int reducedSignatureSizeSingle = ((params.getHeight() / params.getLayers()) + len) * n;
		int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * params.getLayers();
		int totalSize = indexSize + randomSize + reducedSignaturesSizeTotal;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
		XMSSUtil.copyBytesAtOffset(out, indexBytes, position);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, random, position);
		position += randomSize;
		/* copy reduced signatures */
		for(XMSSReducedSignature reducedSignature : reducedSignatures) {
			byte[] signature = reducedSignature.toByteArray();
			XMSSUtil.copyBytesAtOffset(out, signature, position);
			position += reducedSignatureSizeSingle;
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
		int indexSize = (int)Math.ceil(params.getHeight() / (double) 8);
		int randomSize = n;
		int reducedSignatureSizeSingle = ((params.getHeight() / params.getLayers()) + len) * n;
		int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * params.getLayers();
		int totalSize = indexSize + randomSize + reducedSignaturesSizeTotal;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		index = XMSSUtil.bytesToXBigEndian(in, position, indexSize);
		if (!XMSSUtil.isIndexValid(params.getHeight(), index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		random = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
		position += randomSize;
		reducedSignatures = new ArrayList<XMSSReducedSignature>();
		while (position < in.length) {
			XMSSReducedSignature xmssSig = new XMSSReducedSignature(params.getXMSS().getParams());
			xmssSig.parseByteArray(XMSSUtil.extractBytesAtOffset(in, position, reducedSignatureSizeSingle));
			reducedSignatures.add(xmssSig);
			position += reducedSignatureSizeSingle;
		}
	}

	public long getIndex() {
		return index;
	}

	public void setIndex(long index) {
		this.index = index;
	}

	public byte[] getRandom() {
		return random;
	}

	public void setRandom(byte[] random) {
		this.random = random;
	}

	public List<XMSSReducedSignature> getReducedSignatures() {
		return reducedSignatures;
	}

	public void setReducedSignatures(List<XMSSReducedSignature> reducedSignatures) {
		this.reducedSignatures = reducedSignatures;
	}
}
