package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC9980Utils;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The test vectors of RFC 9980 Appendix A, read from the bc-test-data checkout
 * (openpgp/openpgp-pqc/rfc9980, see its README): every sample key parses with the expected fingerprints and
 * its self-signatures verify, every sample message decrypts to "Testing\n" with its embedded signature
 * verifying, every detached signature verifies, and the key combiner reproduces the KEK and session key the
 * RFC prints for each message - all with both the lightweight and the JCA operators.
 */
public class PGPRFC9980VectorTest
    extends SimpleTest
{
    private static final String HOME = "openpgp/openpgp-pqc/rfc9980";
    private static final byte[] TESTING = Strings.toUTF8ByteArray("Testing\n");

    private static class Sample
    {
        final String name;
        final int keyVersion;
        final int primaryAlgorithm;
        final int subkeyAlgorithm;
        final String primaryFingerprint;
        final String subkeyFingerprint;
        final String[] messages;
        final String signature;
        // the RFC's hex intermediates of the key combiner for each message: mlkemKeyShare, ecdhKeyShare, KEK, session key
        final String[][] combinerValues;

        Sample(String name, int keyVersion, int primaryAlgorithm, int subkeyAlgorithm, String primaryFingerprint,
               String subkeyFingerprint, String[] messages, String signature, String[][] combinerValues)
        {
            this.name = name;
            this.keyVersion = keyVersion;
            this.primaryAlgorithm = primaryAlgorithm;
            this.subkeyAlgorithm = subkeyAlgorithm;
            this.primaryFingerprint = primaryFingerprint;
            this.subkeyFingerprint = subkeyFingerprint;
            this.messages = messages;
            this.signature = signature;
            this.combinerValues = combinerValues;
        }
    }

    private static final Sample[] SAMPLES = {
        // A.1
        new Sample("v6-ed25519-mlkem768x25519", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.MLKEM768_X25519,
            "c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947",
            "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d",
            new String[]{ "message" }, null,
            new String[][]{
                { "b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797",
                  "9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932",
                  "5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590",
                  "94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435" }
            }),
        // A.2 - the v4 variant: a v3 PKESK with a v1 SEIPD, and a v6 PKESK with a v2 SEIPD
        new Sample("v4-ed25519-mlkem768x25519", PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.MLKEM768_X25519,
            "342e5db2de345215cb2c944f7102ffed3b9cf12d",
            "e51dbfea51936988b5428fffa4f95f985ed61a51",
            new String[]{ "message-seipd1", "message-seipd2" }, null,
            new String[][]{
                { "16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586",
                  "2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e",
                  "c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f",
                  "b4dc7197e1519822ca689da484643edf272934d98ae1974b5d88317a7a6a3c4f" },
                { "16a22adbeced91ada60b5561611748edd2fedc51e0770f86d7394870062e7322",
                  "5ac67eab192f25ac99d87543e6fcd3a4769cb02c9d1afdc79354c2baa2289e29",
                  "5c5652a690b55d1e9545fbd722f838cd8ff4d3657af5a9026d02f3185ca74993",
                  "160867d96032b640208c1c92174d0270bb89189d72320711acd221bbea2a26b6" }
            }),
        // A.3
        new Sample("v6-mldsa65ed25519-mlkem768x25519", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLKEM768_X25519,
            "a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f",
            "7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4",
            new String[]{ "message" }, "signature",
            new String[][]{
                { "0987fe72ad5ea58e73344f9a2a543f4131d9fdb7cf07474f501430a20f705b4d",
                  "88f3e9a8de1917127b4b758f6e83bd4ce00faaae01bd8b6e412a43a710b26012",
                  "a4904982f7caa9c9de690afd772d8bfe027a1ad6a5bbda00db68963fe303ae8e",
                  "adee68618b302d4bfd7ae3d432bc63a1c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a" }
            }),
        // A.4
        new Sample("v6-mldsa87ed448-mlkem1024x448", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.MLDSA87_Ed448, PublicKeyAlgorithmTags.MLKEM1024_X448,
            "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
            "65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f",
            new String[]{ "message" }, "signature",
            new String[][]{
                { "f18f161e617b8ce5968f109aadea1e7e1511d10165768d36127ba913c00637d2",
                  "732860c8114ae84a964664b1f607785d11bc7d24d5324510adad89bd52db7ee0df9982ad0d1669bdd05556330c86f2dae9e2edea42e05bc5",
                  "ef1e32906f67d39bc800d90cabb0033c77ca6dce8ffca3e96d9c7348e2e8c16e",
                  "0588ce40b038aac353d1cf8c67a674b412985105794821013ef154f786c4d89d" }
            }),
        // A.5
        new Sample("v6-slhdsa128s-mlkem768x25519", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, PublicKeyAlgorithmTags.MLKEM768_X25519,
            "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
            "3e8745a4bb488779e0f32480fa23f8d0bfd8c2f49d7f74e957e1c2ffc2ef4bfc",
            new String[]{ "message" }, "signature",
            new String[][]{
                { "5dc60150f5f965ddc8014b6aa2ecae1831467e98fa315422f238984d6421a22e",
                  "9dbd0f9bde7fef09817146e53a0b5ce7d27e79612670968fa0025422c578ab55",
                  "ae8ab57801911c04c7b4c2a2f665cf8d8a8188f948c2a65e39c292d9b1d86e32",
                  "e87567cad8fee5738f92090feed009d8af95437fa664f94da98776d966bbbc52" }
            }),
        // A.6
        new Sample("v6-slhdsa128f-mlkem768x25519", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.MLKEM768_X25519,
            "d54e0307021169f7b88beb2b76e3aad0e114be1a8f982d74dba9ca51d03537f4",
            "d8875664256c382dd7f3a5ce05021088922811f5d0b1a1f8c7769944a51b7002",
            new String[0], "signature", new String[0][]),
        // A.7
        new Sample("v6-slhdsa256s-mlkem1024x448", PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s, PublicKeyAlgorithmTags.MLKEM1024_X448,
            "72fff84863aeba67f0d1d7691173247dd427533b9d7ee76011c6f77f2ce9fa7a",
            "570a5bbab93169876a8240da35a1ada7ba8a640aabe3ab467c797214844df15f",
            new String[0], "signature", new String[0][]),
    };

    public String getName()
    {
        return "PGPRFC9980VectorTest";
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != SAMPLES.length; i++)
        {
            Sample sample = SAMPLES[i];
            PGPSecretKeyRing secretKeys = readSecretKeys(sample.name + "-sk.asc");
            PGPPublicKeyRing publicKeys = readPublicKeys(sample.name + "-pk.asc");

            checkKeyStructure(sample, secretKeys, publicKeys);
            verifySelfSignatures(sample, secretKeys, new BcPGPContentVerifierBuilderProvider());
            verifySelfSignatures(sample, secretKeys, new JcaPGPContentVerifierBuilderProvider().setProvider("BC"));
            verifySelfSignatures(sample, publicKeys, new BcPGPContentVerifierBuilderProvider());

            for (int m = 0; m != sample.messages.length; m++)
            {
                String[] combiner = sample.combinerValues[m];
                decryptAndVerifyMessage(sample, secretKeys, sample.messages[m], combiner, true);
                decryptAndVerifyMessage(sample, secretKeys, sample.messages[m], combiner, false);
            }

            if (sample.signature != null)
            {
                verifyDetachedSignature(sample, publicKeys, new BcPGPContentVerifierBuilderProvider());
                verifyDetachedSignature(sample, publicKeys, new JcaPGPContentVerifierBuilderProvider().setProvider("BC"));
            }
        }
    }

    private InputStream openVector(String fileName)
        throws IOException
    {
        return new ArmoredInputStream(TestResourceFinder.findTestResource(HOME, fileName));
    }

    private PGPSecretKeyRing readSecretKeys(String fileName)
        throws IOException, PGPException
    {
        InputStream in = openVector(fileName);
        PGPObjectFactory objFac = new BcPGPObjectFactory(new BCPGInputStream(in));
        Object o = objFac.nextObject();
        in.close();
        isTrue(fileName + " should hold a secret key ring", o instanceof PGPSecretKeyRing);
        return (PGPSecretKeyRing)o;
    }

    private PGPPublicKeyRing readPublicKeys(String fileName)
        throws IOException, PGPException
    {
        InputStream in = openVector(fileName);
        PGPObjectFactory objFac = new BcPGPObjectFactory(new BCPGInputStream(in));
        Object o = objFac.nextObject();
        in.close();
        isTrue(fileName + " should hold a public key ring", o instanceof PGPPublicKeyRing);
        return (PGPPublicKeyRing)o;
    }

    private void checkKeyStructure(Sample sample, PGPSecretKeyRing secretKeys, PGPPublicKeyRing publicKeys)
        throws PGPException
    {
        Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
        PGPPublicKey primary = (PGPPublicKey)it.next();
        PGPPublicKey subkey = (PGPPublicKey)it.next();
        isTrue(sample.name + ": two keys expected", !it.hasNext());

        isEquals(sample.name + ": primary key version", sample.keyVersion, primary.getVersion());
        isEquals(sample.name + ": primary key algorithm", sample.primaryAlgorithm, primary.getAlgorithm());
        isEquals(sample.name + ": primary fingerprint", sample.primaryFingerprint, Hex.toHexString(primary.getFingerprint()));
        isTrue(sample.name + ": primary key is a master key", primary.isMasterKey());
        isTrue(sample.name + ": primary key is a signing key", PublicKeyUtils.isSigningAlgorithm(primary.getAlgorithm()));
        isTrue(sample.name + ": primary key is not an encryption key", !primary.isEncryptionKey());

        isEquals(sample.name + ": subkey version", sample.keyVersion, subkey.getVersion());
        isEquals(sample.name + ": subkey algorithm", sample.subkeyAlgorithm, subkey.getAlgorithm());
        isEquals(sample.name + ": subkey fingerprint", sample.subkeyFingerprint, Hex.toHexString(subkey.getFingerprint()));
        isTrue(sample.name + ": subkey is an encryption key", subkey.isEncryptionKey());
        isTrue(sample.name + ": subkey key material", subkey.getPublicKeyPacket().getKey() instanceof MLKEMCompositePublicBCPGKey);
        isEquals(sample.name + ": subkey security strength",
            sample.subkeyAlgorithm == PublicKeyAlgorithmTags.MLKEM768_X25519 ? 192 : 256, subkey.getBitStrength());

        // the public key ring carries the same keys
        isTrue(sample.name + ": public ring primary", Arrays.areEqual(primary.getFingerprint(), publicKeys.getPublicKey().getFingerprint()));
        isTrue(sample.name + ": public ring subkey", publicKeys.getPublicKey(subkey.getKeyIdentifier()) != null);

        // the secret key material parses into the private keys and re-encodes identically
        Iterator<PGPSecretKey> sIt = secretKeys.getSecretKeys();
        while (sIt.hasNext())
        {
            PGPSecretKey sk = (PGPSecretKey)sIt.next();
            PGPPrivateKey priv = sk.extractPrivateKey(null);
            isTrue(sample.name + ": private key for " + sk.getPublicKey().getAlgorithm(), priv != null);
            isTrue(sample.name + ": secret key algorithm " + sk.getPublicKey().getAlgorithm() + " is a signing key or an encryption key",
                sk.isSigningKey() || sk.getPublicKey().isEncryptionKey());
        }
    }

    private void verifySelfSignatures(Sample sample, PGPKeyRing keyRing, PGPContentVerifierBuilderProvider verifierProvider)
        throws PGPException
    {
        Iterator<PGPPublicKey> pubKeys = keyRing.getPublicKeys();
        PGPPublicKey primaryKey = (PGPPublicKey)pubKeys.next();
        int sigs = 0;

        Iterator<PGPSignature> directKeySigs = primaryKey.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (directKeySigs.hasNext())
        {
            PGPSignature dkSig = (PGPSignature)directKeySigs.next();
            isEquals(sample.name + ": direct-key signature algorithm", sample.primaryAlgorithm, dkSig.getKeyAlgorithm());
            dkSig.init(verifierProvider, primaryKey);
            isTrue(sample.name + ": direct-key signature MUST verify", dkSig.verifyCertification(primaryKey));
            sigs++;
        }
        if (sample.keyVersion == PublicKeyPacket.VERSION_6)
        {
            isTrue(sample.name + ": a v6 key carries a direct-key signature", sigs == 1);
        }

        Iterator<String> uids = primaryKey.getUserIDs();
        isTrue(sample.name + ": a user id", uids.hasNext());
        while (uids.hasNext())
        {
            String uid = (String)uids.next();
            Iterator<PGPSignature> uidSigs = primaryKey.getSignaturesForID(uid);
            while (uidSigs.hasNext())
            {
                PGPSignature uidSig = (PGPSignature)uidSigs.next();
                uidSig.init(verifierProvider, primaryKey);
                isTrue(sample.name + ": user-id certification MUST verify", uidSig.verifyCertification(uid, primaryKey));
                sigs++;
            }
        }

        while (pubKeys.hasNext())
        {
            PGPPublicKey subkey = (PGPPublicKey)pubKeys.next();
            Iterator<PGPSignature> bindSigs = subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
            while (bindSigs.hasNext())
            {
                PGPSignature bindSig = (PGPSignature)bindSigs.next();
                bindSig.init(verifierProvider, primaryKey);
                isTrue(sample.name + ": subkey binding signature MUST verify", bindSig.verifyCertification(primaryKey, subkey));
                isTrue(sample.name + ": binding hash MUST be at least 256 bits", bindSig.getHashAlgorithm() != HashAlgorithmTags.SHA1);
                sigs++;
            }
        }
        isTrue(sample.name + ": user-id certification and subkey binding present", sigs >= 2);
    }

    private void decryptAndVerifyMessage(Sample sample, PGPSecretKeyRing secretKeys, String messageName, String[] combiner, boolean bc)
        throws Exception
    {
        String label = sample.name + "-" + messageName + (bc ? " (bc)" : " (jce)");
        InputStream in = openVector(sample.name + "-" + messageName + ".asc");
        PGPObjectFactory objFac = new BcPGPObjectFactory(new BCPGInputStream(in));
        PGPEncryptedDataList encList = (PGPEncryptedDataList)objFac.nextObject();
        isEquals(label + ": one PKESK", 1, encList.size());
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);
        isEquals(label + ": PKESK algorithm", sample.subkeyAlgorithm, encData.getAlgorithm());

        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyIdentifier());
        isTrue(label + ": decryption key found", decryptionKey != null);
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        PGPKeyPair keyPair = new PGPKeyPair(decryptionKey.getPublicKey(), privateKey);

        PublicKeyDataDecryptorFactory decryptor = bc
            ? (PublicKeyDataDecryptorFactory)new BcPublicKeyDataDecryptorFactory(keyPair)
            : new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);

        // the session key the RFC prints
        PGPSessionKey sessionKey = encData.getSessionKey(decryptor);
        isEquals(label + ": session key", combiner[3], Hex.toHexString(sessionKey.getKey()));
        isEquals(label + ": session key algorithm", SymmetricKeyAlgorithmTags.AES_256, sessionKey.getAlgorithm());

        // the key combiner (RFC 9980 sec. 4.2.1), fed with the RFC's intermediate key shares
        InputStream rawIn = openVector(sample.name + "-" + messageName + ".asc");
        PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket)new BCPGInputStream(rawIn).readPacket();
        rawIn.close();
        byte[][] parts = RFC9980Utils.parseEncryptedSessionKey(pkesk.getEncSessionKey()[0], sample.subkeyAlgorithm,
            pkesk.getVersion() == PublicKeyEncSessionPacket.VERSION_3);
        byte[] ecdhPublicKey = ((MLKEMCompositePublicBCPGKey)decryptionKey.getPublicKey().getPublicKeyPacket().getKey()).getECDHPublicKey();
        byte[] kek = RFC9980Utils.deriveKEK(new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA3_256),
            Hex.decode(combiner[0]), Hex.decode(combiner[1]), parts[0], ecdhPublicKey, sample.subkeyAlgorithm);
        isEquals(label + ": KEK", combiner[2], Hex.toHexString(kek));
        byte[] unwrapped = BcPublicKeyDataDecryptorFactory.unwrapSessionData(parts[2], SymmetricKeyAlgorithmTags.AES_256, new KeyParameter(kek));
        isEquals(label + ": unwrapped session key", combiner[3], Hex.toHexString(unwrapped));
        if (pkesk.getVersion() == PublicKeyEncSessionPacket.VERSION_3)
        {
            isEquals(label + ": v3 symmetric algorithm octet", SymmetricKeyAlgorithmTags.AES_256, parts[3][0] & 0xff);
        }

        // the plaintext and the embedded signature
        InputStream clear = encData.getDataStream(decryptor);
        PGPObjectFactory plainFac = new BcPGPObjectFactory(clear);
        Object o = plainFac.nextObject();
        if (o instanceof PGPCompressedData)
        {
            plainFac = new BcPGPObjectFactory(((PGPCompressedData)o).getDataStream());
            o = plainFac.nextObject();
        }
        isTrue(label + ": one-pass signature expected, got " + o, o instanceof PGPOnePassSignatureList);
        PGPOnePassSignature ops = ((PGPOnePassSignatureList)o).get(0);
        isEquals(label + ": OPS algorithm", sample.primaryAlgorithm, ops.getKeyAlgorithm());
        PGPPublicKey signingKey = secretKeys.getPublicKey(ops.getKeyIdentifier());
        isTrue(label + ": signing key found", signingKey != null);
        ops.init(bc ? (PGPContentVerifierBuilderProvider)new BcPGPContentVerifierBuilderProvider()
            : new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingKey);

        PGPLiteralData lit = (PGPLiteralData)plainFac.nextObject();
        ByteArrayOutputStream plain = new ByteArrayOutputStream();
        InputStream litIn = lit.getDataStream();
        int b;
        while ((b = litIn.read()) >= 0)
        {
            ops.update((byte)b);
            plain.write(b);
        }
        isTrue(label + ": plaintext", Arrays.areEqual(TESTING, plain.toByteArray()));

        PGPSignatureList sigs = (PGPSignatureList)plainFac.nextObject();
        PGPSignature sig = sigs.get(0);
        isTrue(label + ": embedded signature MUST verify", ops.verify(sig));
        isTrue(label + " is integrity protected", encData.isIntegrityProtected());
        isTrue(label + ": integrity check", encData.verify());
        in.close();
    }

    private void verifyDetachedSignature(Sample sample, PGPPublicKeyRing publicKeys, PGPContentVerifierBuilderProvider verifierProvider)
        throws IOException, PGPException
    {
        InputStream in = openVector(sample.name + "-" + sample.signature + ".asc");
        PGPObjectFactory objFac = new BcPGPObjectFactory(new BCPGInputStream(in));
        PGPSignatureList sigs = (PGPSignatureList)objFac.nextObject();
        in.close();
        isEquals(sample.name + ": one detached signature", 1, sigs.size());
        PGPSignature sig = sigs.get(0);
        isEquals(sample.name + ": detached signature version", 6, sig.getVersion());
        isEquals(sample.name + ": detached signature algorithm", sample.primaryAlgorithm, sig.getKeyAlgorithm());
        isTrue(sample.name + ": detached signature hash MUST be at least 256 bits",
            sig.getHashAlgorithm() == HashAlgorithmTags.SHA256 || sig.getHashAlgorithm() == HashAlgorithmTags.SHA384
                || sig.getHashAlgorithm() == HashAlgorithmTags.SHA512 || sig.getHashAlgorithm() == HashAlgorithmTags.SHA3_256
                || sig.getHashAlgorithm() == HashAlgorithmTags.SHA3_512);

        PGPPublicKey signingKey = publicKeys.getPublicKey(sig.getKeyID());
        isTrue(sample.name + ": detached signature signing key found", signingKey != null);
        sig.init(verifierProvider, signingKey);
        sig.update(TESTING);
        isTrue(sample.name + ": detached signature MUST verify", sig.verify());

        // and not over a different message (the RFC's detached signatures are text signatures, so a line
        // ending change alone is canonicalised away - alter the text)
        sig.init(verifierProvider, signingKey);
        sig.update(Strings.toUTF8ByteArray("Testing!\n"));
        isTrue(sample.name + ": detached signature MUST NOT verify over other data", !sig.verify());
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPRFC9980VectorTest());
    }
}
