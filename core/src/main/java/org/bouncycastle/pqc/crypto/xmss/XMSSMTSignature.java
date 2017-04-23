package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSSMT Signature.
 *
 */
public final class XMSSMTSignature implements XMSSStoreableObjectInterface {

	private final XMSSMTParameters params;
	private final long index;
	private final byte[] random;
	private final List<XMSSReducedSignature> reducedSignatures;

	private XMSSMTSignature(Builder builder) throws ParseException {
		super();
		params = builder.params;
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		int n = params.getDigestSize();
		byte[] signature = builder.signature;
		if (signature != null) {
			/* import */
			int len = params.getWOTSPlus().getParams().getLen();
			int indexSize = (int) Math.ceil(params.getHeight() / (double) 8);
			int randomSize = n;
			int reducedSignatureSizeSingle = ((params.getHeight() / params.getLayers()) + len) * n;
			int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * params.getLayers();
			int totalSize = indexSize + randomSize + reducedSignaturesSizeTotal;
			if (signature.length != totalSize) {
				throw new ParseException("signature has wrong size", 0);
			}
			int position = 0;
			index = XMSSUtil.bytesToXBigEndian(signature, position, indexSize);
			if (!XMSSUtil.isIndexValid(params.getHeight(), index)) {
				throw new ParseException("index out of bounds", 0);
			}
			position += indexSize;
			random = XMSSUtil.extractBytesAtOffset(signature, position, randomSize);
			position += randomSize;
			reducedSignatures = new ArrayList<XMSSReducedSignature>();
			while (position < signature.length) {
				XMSSReducedSignature xmssSig = new XMSSReducedSignature.Builder(params.getXMSS().getParams())
						.withReducedSignature(XMSSUtil.extractBytesAtOffset(signature, position, reducedSignatureSizeSingle))
						.build();
				reducedSignatures.add(xmssSig);
				position += reducedSignatureSizeSingle;
			}
		} else {
			/* set */
			index = builder.index;
			byte[] tmpRandom = builder.random;
			if (tmpRandom != null) {
				if (tmpRandom.length != n) {
					throw new IllegalArgumentException("size of random needs to be equal to size of digest");
				}
				random = tmpRandom;
			} else {
				random = new byte[n];
			}
			List<XMSSReducedSignature> tmpReducedSignatures = builder.reducedSignatures;
			if (tmpReducedSignatures != null) {
				reducedSignatures = tmpReducedSignatures;
			} else {
				reducedSignatures = new ArrayList<XMSSReducedSignature>();
			}
		}
	}

	public static class Builder {
		
		/* mandatory */
		private final XMSSMTParameters params;
		/* optional */
		private long index = 0L;
		private byte[] random = null;
		private List<XMSSReducedSignature> reducedSignatures = null;
		private byte[] signature = null;
		
		public Builder(XMSSMTParameters params) {
			super();
			this.params = params;
		}
		
		public Builder withIndex(long val) {
			index = val;
			return this;
		}
		
		public Builder withRandom(byte[] val) {
			random = XMSSUtil.cloneArray(val);
			return this;
		}
		
		public Builder withReducedSignatures(List<XMSSReducedSignature> val) {
			reducedSignatures = val;
			return this;
		}

		public Builder withSignature(byte[] val) {
			signature = val;
			return this;
		}

		public XMSSMTSignature build() throws ParseException {
			return new XMSSMTSignature(this);
		}
	}

	public byte[] toByteArray() {
		/* index || random || reduced signatures */
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int indexSize = (int) Math.ceil(params.getHeight() / (double) 8);
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
		for (XMSSReducedSignature reducedSignature : reducedSignatures) {
			byte[] signature = reducedSignature.toByteArray();
			XMSSUtil.copyBytesAtOffset(out, signature, position);
			position += reducedSignatureSizeSingle;
		}
		return out;
	}

	public long getIndex() {
		return index;
	}

	public byte[] getRandom() {
		return XMSSUtil.cloneArray(random);
	}

	public List<XMSSReducedSignature> getReducedSignatures() {
		return reducedSignatures;
	}
}
