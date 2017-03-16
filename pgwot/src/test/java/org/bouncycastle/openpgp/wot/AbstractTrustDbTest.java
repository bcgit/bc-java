package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.bouncycastle.openpgp.wot.key.PgpKeyId;
import org.bouncycastle.openpgp.wot.key.PgpKeyRegistry;
import org.bouncycastle.openpgp.wot.key.PgpKeyRegistryImpl;
import org.bouncycastle.openpgp.wot.key.PgpUserId;
import org.junit.After;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractTrustDbTest {
	private static final Logger logger = LoggerFactory.getLogger(AbstractTrustDbTest.class);

	/**
	 * Skip cleaning up after a test run. This is useful to analyse the situation manually, after a test
	 * was run.
	 */
	protected static final boolean SKIP_CLEANUP = Boolean.parseBoolean(System.getProperty("SKIP_CLEANUP"));

	/**
	 * Skip additionally running 'gpg --check-trustdb --homedir ${tempGnuPgDir}' and comparing its results with
	 * the results of the Java code.
	 */
	protected static final boolean SKIP_GPG_CHECK_TRUST_DB = Boolean.parseBoolean(System.getProperty("SKIP_GPG_CHECK_TRUST_DB"));

	private final long validitySeconds = 365L * 24L * 3600L;
	protected final SecureRandom secureRandom = new SecureRandom();

	protected File tempDir;
	protected File gnupgHomeDir;

	protected File pubringFile;
	protected File secringFile;
	protected File trustdbFile;

	protected PgpKeyRegistry pgpKeyRegistry;

	@Before
	public void before() throws Exception {
		File tempFile = File.createTempFile("abc-", ".tmp");
		tempDir = tempFile.getParentFile().getAbsoluteFile();
		tempFile.delete();
		initGnupgHomeDir();

		pubringFile = new File(gnupgHomeDir, "pubring.gpg");
		secringFile = new File(gnupgHomeDir, "secring.gpg");
		trustdbFile = new File(gnupgHomeDir, "trustdb.gpg");

		pgpKeyRegistry = new PgpKeyRegistryImpl(pubringFile, secringFile);
	}

	@After
	public void after() throws Exception {
		if (gnupgHomeDir != null) {
			deleteGnupgHomeDir();
			gnupgHomeDir = null;
		}
	}

	protected void initGnupgHomeDir() {
		gnupgHomeDir = new File(tempDir, "gnupg_" + Long.toHexString(System.currentTimeMillis()) + '_' + Integer.toHexString(Math.abs(secureRandom.nextInt())));
		gnupgHomeDir.mkdir();
	}

	protected void deleteGnupgHomeDir() {
		if (SKIP_CLEANUP)
			logger.warn("SKIP_CLEANUP is true => *NOT* deleting directory: {}", gnupgHomeDir);
		else
			deleteRecursively(gnupgHomeDir);
	}

	protected void runGpgCheckTrustDb() throws IOException, InterruptedException {
		ProcessBuilder processBuilder = new ProcessBuilder("gpg", "--check-trustdb", "--homedir", gnupgHomeDir.getPath());
		processBuilder.redirectErrorStream(true);
		Process process = processBuilder.start();
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final InputStream inputStream = process.getInputStream();
		new Thread() {
			@Override
			public void run() {
				try {
					final byte[] buf = new byte[1024 * 1024];
					int bytesRead;
					while ((bytesRead = inputStream.read(buf)) >= 0) {
						output.write(buf, 0, bytesRead);
						try {
							logger.info("runGpg: {}", new String(buf, 0, bytesRead, StandardCharsets.UTF_8));
						} catch (Exception x) {
							logger.warn("runGpg: Output could not be read into String: " + x, x);
						}
					}
				} catch (Exception x) {
					logger.error("runGpg: " + x, x);
				}
			}
		}.start();

		String outputString;
		try {
			outputString = new String(output.toByteArray());
		} catch (Exception x) {
			outputString = null;
			logger.warn("runGpg: Output could not be read into String: " + x, x);
		}

		int processResult = process.waitFor();
		if (processResult != 0)
			throw new IOException("gpg failed with error-code " + processResult + " and the following output:\n\n" + outputString);
	}

	private static void deleteRecursively(File fileOrDir) {
		assertNotNull("fileOrDir", fileOrDir);
		fileOrDir.delete(); // first try to delete - if this is a symlink, this already succeeds

		File[] children = fileOrDir.listFiles();
		if (children != null) {
			for (File child : children)
				deleteRecursively(child);
		}

		fileOrDir.delete(); // delete (maybe again) after the children are gone.
	}

	protected PGPSecretKeyRingCollection readSecretKeyRingCollection() throws IOException, PGPException {
		if (!secringFile.exists())
			secringFile.createNewFile();

		try (InputStream in = new BufferedInputStream(new FileInputStream(secringFile));) {
			return new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
		}
	}

	protected void writeSecretKeyRingCollection(PGPSecretKeyRingCollection collection) throws IOException, PGPException {
		try (OutputStream out = new BufferedOutputStream(new FileOutputStream(secringFile));) {
			collection.encode(out);
		}
	}

	protected PGPPublicKeyRingCollection readPublicKeyRingCollection() throws IOException, PGPException {
		if (!pubringFile.exists())
			pubringFile.createNewFile();

		try (InputStream in = new BufferedInputStream(new FileInputStream(pubringFile));) {
			return new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
		}
	}

	protected void writePublicKeyRingCollection(PGPPublicKeyRingCollection collection) throws IOException, PGPException {
		try (OutputStream out = new BufferedOutputStream(new FileOutputStream(pubringFile));) {
			collection.encode(out);
		}
	}

	public PgpKey signPublicKey(PgpKey signingKey, int certificationType, PgpKey signedKey) throws IOException, PGPException {
		assertNotNull("signingKey", signingKey);
		assertNotNull("signedKey", signedKey);

		signedKey = pgpKeyRegistry.getPgpKey(signedKey.getPgpKeyId()); // maybe the given signedKey is stale!

		// null causes an exception - empty is possible, though
		final char[] passphrase = new char[0];

		if (signingKey.getMasterKey() != null)
			signingKey = signingKey.getMasterKey(); // TODO should we maybe search for a separate signing-key?

		if (signedKey.getMasterKey() != null)
			throw new IllegalArgumentException("signedKeyId does not reference a master-key! Cannot sign sub-keys!");

//		final int masterKeyAlgorithm = PublicKeyAlgorithmTags.RSA_SIGN;
		final int masterKeyAlgorithm = signingKey.getPublicKey().getAlgorithm();

		PGPSecretKey secretKey = assertNotNull("signingKey.secretKey", signingKey.getSecretKey());
		PGPPrivateKey privateKey = extractPrivateKey(secretKey, passphrase);

		final BcPGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(masterKeyAlgorithm, HashAlgorithmTags.SHA512);
		final PGPSignatureGenerator sGen = new PGPSignatureGenerator(signerBuilder);

		sGen.init(certificationType, privateKey);

		final PGPSignatureSubpacketGenerator subpckGen = new PGPSignatureSubpacketGenerator();

		// Using KeyFlags instead of PGPKeyFlags, because the latter seem incomplete.
//		masterSubpckGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.AUTHENTICATION);
//		masterSubpckGen.setPreferredSymmetricAlgorithms(false, preferredSymmetricAlgorithms);
//		masterSubpckGen.setPreferredHashAlgorithms(false, preferredHashAlgorithms);
//		masterSubpckGen.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZIP });
		subpckGen.setKeyExpirationTime(false, validitySeconds);

		sGen.setHashedSubpackets(subpckGen.generate());
		sGen.setUnhashedSubpackets(null); // AFAIK not needed

		PGPPublicKey signedPublicKey = signedKey.getPublicKey();
		for (PgpUserId pgpUserId : signedKey.getPgpUserIds()) {
			String userId = pgpUserId.getUserId();
			if (userId == null)
				throw new UnsupportedOperationException("Signing UserAttributes not yet supported!");

			final PGPSignature certification = sGen.generateCertification(userId, signedPublicKey);
			signedPublicKey = PGPPublicKey.addCertification(signedPublicKey, userId, certification);
		}

		PGPPublicKeyRingCollection publicKeyRingCollection = readPublicKeyRingCollection();
		publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, signedKey.getPublicKeyRing());

		PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.removePublicKey(signedKey.getPublicKeyRing(), signedKey.getPublicKey());
		publicKeyRing = PGPPublicKeyRing.insertPublicKey(publicKeyRing, signedPublicKey);

		publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, publicKeyRing);
		writePublicKeyRingCollection(publicKeyRingCollection);

		pgpKeyRegistry.markStale();
		return pgpKeyRegistry.getPgpKeyOrFail(signedKey.getPgpKeyId());
	}

	public PgpKey createPgpKey(final String userId) throws NoSuchAlgorithmException, IOException, PGPException {
		assertNotNull("userId", userId);

		// null causes an exception - empty is possible, though
		char[] passphrase = new char[0];

		final Pair<PGPPublicKeyRing, PGPSecretKeyRing> pair = createPGPSecretKeyRing(userId, passphrase);
		final PGPPublicKeyRing publicKeyRing = pair.a;
		final PGPSecretKeyRing secretKeyRing = pair.b;

		PGPSecretKeyRingCollection secretKeyRingCollection = readSecretKeyRingCollection();
		secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection, secretKeyRing);
		writeSecretKeyRingCollection(secretKeyRingCollection);

		PGPPublicKeyRingCollection publicKeyRingCollection = readPublicKeyRingCollection();
		publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, publicKeyRing);
		writePublicKeyRingCollection(publicKeyRingCollection);

		final PGPSecretKey secretKey = secretKeyRing.getSecretKey();

		pgpKeyRegistry.markStale();
		return pgpKeyRegistry.getPgpKeyOrFail(new PgpKeyId(secretKey.getKeyID()));
	}

	private static final class Pair<A, B> {
		public final A a;
		public final B b;

		public Pair(A a, B b) {
			this.a = a;
			this.b = b;
		}
	}

	private static PGPPrivateKey extractPrivateKey(final PGPSecretKey secretKey, final char[] passphrase) throws PGPException {
		final PGPPrivateKey privateKey = secretKey.extractPrivateKey(
				new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passphrase));

		return privateKey;
	}

	private Pair<PGPPublicKeyRing, PGPSecretKeyRing> createPGPSecretKeyRing(final String userId, final char[] passphrase) throws PGPException, NoSuchAlgorithmException {
		assertNotNull("userId", userId);
		assertNotNull("passphrase", passphrase);

		logger.info("createPGPSecretKeyRing: Creating PGP key: userId='{}'", userId);

		final Date now = new Date();

		final int masterKeyAlgorithm = PublicKeyAlgorithmTags.RSA_SIGN;
		final int subKey1Algorithm = PublicKeyAlgorithmTags.RSA_ENCRYPT;
		final int secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTags.TWOFISH;

		final int[] preferredHashAlgorithms = new int[] { // TODO configurable?!
				HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1
		};

		final int[] preferredSymmetricAlgorithms = new int[] { // TODO configurable?!
				SymmetricKeyAlgorithmTags.TWOFISH, SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.BLOWFISH
		};

		logger.info("createPGPSecretKeyRing: Creating masterKeyPairGenerator...");
		final AsymmetricCipherKeyPairGenerator masterKeyPairGenerator = createAsymmetricCipherKeyPairGenerator();

		logger.info("createPGPSecretKeyRing: Creating sub1KeyPairGenerator...");
		final AsymmetricCipherKeyPairGenerator sub1KeyPairGenerator = createAsymmetricCipherKeyPairGenerator();


		/* Create the master (signing-only) key. */
		logger.info("createPGPSecretKeyRing: Creating masterKeyPair...");
		final BcPGPKeyPair masterKeyPair = new BcPGPKeyPair(masterKeyAlgorithm, masterKeyPairGenerator.generateKeyPair(), now);

		final PGPSignatureSubpacketGenerator masterSubpckGen = new PGPSignatureSubpacketGenerator();

		// Using KeyFlags instead of PGPKeyFlags, because the latter seem incomplete.
		masterSubpckGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.AUTHENTICATION);
		masterSubpckGen.setPreferredSymmetricAlgorithms(false, preferredSymmetricAlgorithms);
		masterSubpckGen.setPreferredHashAlgorithms(false, preferredHashAlgorithms);
		masterSubpckGen.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZIP });
		masterSubpckGen.setKeyExpirationTime(false, validitySeconds);


		/* Create an encryption sub-key. */
		logger.info("createPGPSecretKeyRing: Creating sub1KeyPair...");
		final BcPGPKeyPair sub1KeyPair = new BcPGPKeyPair(subKey1Algorithm, sub1KeyPairGenerator.generateKeyPair(), now);

		final PGPSignatureSubpacketGenerator sub1SubpckGen = new PGPSignatureSubpacketGenerator();

		sub1SubpckGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
		sub1SubpckGen.setPreferredSymmetricAlgorithms(false, preferredSymmetricAlgorithms);
		sub1SubpckGen.setPreferredHashAlgorithms(false, preferredHashAlgorithms);
		sub1SubpckGen.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZIP });
		sub1SubpckGen.setKeyExpirationTime(false, validitySeconds);


		/* Create the key ring. */
		logger.info("createPGPSecretKeyRing: Creating keyRingGenerator...");
		final BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
		final BcPGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(masterKeyAlgorithm, HashAlgorithmTags.SHA512);
		final BcPBESecretKeyEncryptorBuilder pbeSecretKeyEncryptorBuilder = new BcPBESecretKeyEncryptorBuilder(
				secretKeyEncryptionAlgorithm, digestCalculatorProvider.get(HashAlgorithmTags.SHA512));

		// Tried SHA512 for checksumCalculator => org.bouncycastle.openpgp.PGPException: only SHA1 supported for key checksum calculations.
		final PGPDigestCalculator checksumCalculator = digestCalculatorProvider.get(HashAlgorithmTags.SHA1);

		final PGPSignatureSubpacketVector hashedSubpackets = masterSubpckGen.generate();
		final PGPSignatureSubpacketVector unhashedSubpackets = null;
		PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
				PGPSignature.POSITIVE_CERTIFICATION,
				masterKeyPair,
				userId,
				checksumCalculator,
				hashedSubpackets,
				unhashedSubpackets,
				signerBuilder,
				pbeSecretKeyEncryptorBuilder.build(passphrase));


		/* Add encryption subkey. */
		keyRingGenerator.addSubKey(sub1KeyPair, sub1SubpckGen.generate(), null);


		/* Generate the key ring. */
		logger.info("createPGPSecretKeyRing: generateSecretKeyRing...");
		PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();

		logger.info("createPGPSecretKeyRing: generatePublicKeyRing...");
		PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();

		logger.info("createPGPSecretKeyRing: all done!");
		return new Pair<>(publicKeyRing,  secretKeyRing);
	}

	private static PGPPublicKey getMasterKeyOrFail(final PGPPublicKeyRing publicKeyRing) {
		for (Iterator<?> it = publicKeyRing.getPublicKeys(); it.hasNext(); ) {
			PGPPublicKey pk = (PGPPublicKey) it.next();
			if (pk.isMasterKey()) {
				return pk;
			}
		}
		throw new IllegalStateException("No masterKey found!");
	}

	private AsymmetricCipherKeyPairGenerator createAsymmetricCipherKeyPairGenerator() throws NoSuchAlgorithmException {
		AsymmetricCipherKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
		keyPairGenerator.init(createRsaKeyGenerationParameters());
		return keyPairGenerator;
	}

	private RSAKeyGenerationParameters createRsaKeyGenerationParameters() {
		/*
		 * This value should be a Fermat number. 0x10001 (F4) is current recommended value. 3 (F1) is known to be safe also.
		 * 3, 5, 17, 257, 65537, 4294967297, 18446744073709551617,
		 * <p>
		 * Practically speaking, Windows does not tolerate public exponents which do not fit in a 32-bit unsigned integer.
		 * Using e=3 or e=65537 works "everywhere".
		 * <p>
		 * See: <a href="http://stackoverflow.com/questions/11279595/rsa-public-exponent-defaults-to-65537-what-should-this-value-be-what-are-the">stackoverflow: RSA Public exponent defaults to 65537. ... What are the impacts of my choices?</a>
		 */
		final BigInteger publicExponent = BigInteger.valueOf(0x10001);

		/*
		 * How certain do we want to be that the chosen primes are really primes.
		 * <p>
		 * The higher this number, the more tests are done to make sure they are primes (and not composites).
		 * <p>
		 * See: <a href="http://crypto.stackexchange.com/questions/3114/what-is-the-correct-value-for-certainty-in-rsa-key-pair-generation">What is the correct value for “certainty” in RSA key pair generation?</a>
		 * and
		 * <a href="http://crypto.stackexchange.com/questions/3126/does-a-high-exponent-compensate-for-a-low-degree-of-certainty?lq=1">Does a high exponent compensate for a low degree of certainty?</a>
		 */
		final int certainty = 12;

		return new RSAKeyGenerationParameters(
				publicExponent, secureRandom, 1024, certainty); // IMPORTANT 1024 is TOO WEAK for productive use, but we want it to be fast for our tests!
	}
}
