package org.bouncycastle.crypto.agreement.kdf;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Pack;

/**
 * X9.63 based key derivation function for ECDH CMS.
 *
 * @author rainer.schubert
 *
 */
public class ECKaEgKEKGenerator extends DHKEKGenerator {
	private DigestDerivationFunction kdf;

	private ASN1ObjectIdentifier algorithm;
	private int keySize;
	private byte[] z;
	private boolean addSharedInfo;

	public static boolean USE_SHARED_INFO = true;
	public static boolean DONTUSE_SHARED_INFO = false;

	public ECKaEgKEKGenerator(Digest digest, boolean addSharedInfo) {
		super(digest);
		this.kdf = new KDF2BytesGenerator(digest);
		this.addSharedInfo = addSharedInfo;
	}

	public ECKaEgKEKGenerator(Digest digest) {
		super(digest);
		this.kdf = new KDF2BytesGenerator(digest);
		this.addSharedInfo = true;
	}

	@Override
	public void init(DerivationParameters param) {
		DHKDFParameters params = (DHKDFParameters) param;

		this.algorithm = params.getAlgorithm();
		this.keySize = params.getKeySize();
		this.z = params.getZ();
	}

	@Override
	public Digest getDigest() {
		return kdf.getDigest();
	}

	@Override
	public int generateBytes(byte[] out, int outOff, int len)
			throws DataLengthException, IllegalArgumentException
	{
		byte[] sharedInfo = null;

		if (addSharedInfo) {
			// TODO Create an ASN.1 class for this (RFC3278)
			// ECC-CMS-SharedInfo
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new AlgorithmIdentifier(algorithm, DERNull.INSTANCE));
			v.add(new DERTaggedObject(true, 2, new DEROctetString(Pack.intToBigEndian(keySize))));

			try {
				sharedInfo = new DERSequence(v).getEncoded(ASN1Encoding.DER);
			} catch (IOException e) {
				throw new IllegalArgumentException("unable to initialise kdf: " + e.getMessage());
			}
		}

		kdf.init(new KDFParameters(z, sharedInfo));

		return kdf.generateBytes(out, outOff, len);
	}
}
