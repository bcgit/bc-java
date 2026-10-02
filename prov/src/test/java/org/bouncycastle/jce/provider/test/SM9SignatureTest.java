package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.gm.SM9Signature;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.signers.SM9Signer;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserKeyGenerator;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPublicKey;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * JCE-level tests for the SM9 signature algorithm exposed through
 * the BouncyCastle provider's GM family.
 */
public class SM9SignatureTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Signature";
    }

    public void performTest()
        throws Exception
    {
        // SM9 has one curve, so 256 is the only strength. The two master key generators share one
        // implementation, told apart by the lightweight generator each drives, the keys each hands
        // back and the message a spec gets
        String[] generators = { "SM9-SIGN", "SM9-ENC" };
        String[] userKeyPairSources = { "SM9SigMasterPrivateKey.generateUserKeyPair()",
            "SM9EncMasterPrivateKey.generateUserKeyPair(identity, hid)" };
        Class[] masterKeys = { SM9SigMasterPrivateKey.class, org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey.class };
        for (int i = 0; i != generators.length; i++)
        {
            try
            {
                KeyPairGenerator.getInstance(generators[i], "BC").initialize(384);
                fail(generators[i] + " accepted a strength of 384");
            }
            catch (java.security.InvalidParameterException e)
            {
                isTrue(("SM9 is defined only on its 256-bit curve; strength must be 256, not 384")
                    .equals(e.getMessage()));
            }
            KeyPairGenerator.getInstance(generators[i], "BC").initialize(256);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(generators[i], "BC");
            try
            {
                kpg.initialize(new java.security.spec.AlgorithmParameterSpec()
                {
                });
                fail(generators[i] + " accepted an AlgorithmParameterSpec");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                isTrue((generators[i] + " master key generation takes no AlgorithmParameterSpec; user key pairs come from "
                    + userKeyPairSources[i]).equals(e.getMessage()));
            }
            KeyPair generated = kpg.generateKeyPair();
            isTrue(generators[i] + " generates its own master key pair without initialize()",
                masterKeys[i].isInstance(generated.getPrivate()) && generators[i].equals(generated.getPublic().getAlgorithm()));
        }

        // a parameterless scheme reports no parameters rather than throwing
        isTrue("Signature.SM9 has no parameters to report", Signature.getInstance("SM9", "BC").getParameters() == null);

        byte[] identityAlice = "Alice".getBytes("US-ASCII");
        byte[] message = "Chinese IBS standard".getBytes("US-ASCII");

        // 1. derive Alice's key pair from a master key pair, sign and verify - the verifier forms
        //    Alice's public key from the master public key and her identity
        KeyPair masterPair = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        SM9SigMasterPrivateKey masterPriv = (SM9SigMasterPrivateKey)masterPair.getPrivate();
        SM9SigMasterPublicKey masterPub = (SM9SigMasterPublicKey)masterPair.getPublic();
        KeyPair alice = masterPriv.generateUserKeyPair(identityAlice);

        // the KGC extraction is also reachable through the capability interface
        SM9SigUserKeyGenerator kgc = masterPriv;
        isTrue("SM9SigUserKeyGenerator derives the same user key",
            Arrays.areEqual(alice.getPrivate().getEncoded(),
                kgc.generateUserKeyPair(identityAlice).getPrivate().getEncoded()));

        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(alice.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SM9", "BC");
        verifier.initVerify(masterPub.getUserPublicKey(identityAlice));
        verifier.update(message);
        isTrue("SM9 JCE sign/verify round-trip", verifier.verify(sig));

        // the KGC-generated public half and the verifier-derived key are the same key
        isTrue("SM9 user public key halves agree",
            alice.getPublic().equals(masterPub.getUserPublicKey(identityAlice)));

        // the user keys carry their identity, and the public key its master public key
        isTrue("SM9 sign user private key identity",
            Arrays.areEqual(identityAlice, ((SM9SigUserPrivateKey)alice.getPrivate()).getIdentity()));
        SM9SigUserPublicKey alicePublic = (SM9SigUserPublicKey)alice.getPublic();
        isTrue("SM9 sign user public key identity", Arrays.areEqual(identityAlice, alicePublic.getIdentity()));
        isTrue("SM9 sign user public key master public key",
            Arrays.areEqual(masterPub.getEncoded(), alicePublic.getMasterPublicKey().getEncoded()));

        // 2. verifying against the wrong identity must fail
        Signature wrongIdentity = Signature.getInstance("SM9", "BC");
        wrongIdentity.initVerify(masterPub.getUserPublicKey("Bob".getBytes("US-ASCII")));
        wrongIdentity.update(message);
        isTrue("SM9 JCE rejects wrong identity", !wrongIdentity.verify(sig));

        // ... and there is no signer public key for an empty identity
        try
        {
            masterPub.getUserPublicKey(new byte[0]);
            fail("SM9 signature master public key gave a user public key for an empty identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("identity cannot be empty".equals(e.getMessage()));
        }

        // 3. a zero-length message signs and verifies - with no update() on either side
        Signature emptySigner = Signature.getInstance("SM9", "BC");
        emptySigner.initSign(alice.getPrivate());
        byte[] emptySig = emptySigner.sign();

        Signature emptyVerifier = Signature.getInstance("SM9", "BC");
        emptyVerifier.initVerify(masterPub.getUserPublicKey(identityAlice));
        isTrue("SM9 JCE zero-length message round-trip", emptyVerifier.verify(emptySig));

        // 4. the provider verifies the GM/T 0044.5 Annex A signature, with the master key rebuilt
        //    through the KeyFactory's PKCS#8 path
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        byte[] katScalar = BigIntegers.asUnsignedByteArray(32,
            new java.math.BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16));
        PrivateKeyInfo katPkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), new DEROctetString(katScalar));
        SM9SigMasterPrivateKey katMaster = (SM9SigMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(katPkcs8.getEncoded()));
        PublicKey katAlice = katMaster.generateUserKeyPair(identityAlice).getPublic();
        byte[] katSig = new SM9Signature(
            Hex.decode("823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB"),  // h
            Hex.decode("04"                                                                    // uncompressed S
                + "73BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C"           // Sx
                + "856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05"))         // Sy
            .getEncoded(ASN1Encoding.DER);
        Signature katVerifier = Signature.getInstance("SM9", "BC");
        katVerifier.initVerify(katAlice);
        katVerifier.update(message);
        isTrue("SM9 JCE verifies GM/T 0044.5 KAT signature", katVerifier.verify(katSig));

        // ... and produces it: handed the annex's r, the provider signs to the annex's signature
        // byte for byte, which a signature that merely verifies against itself does not show
        Signature katSigner = Signature.getInstance("SM9", "BC");
        katSigner.initSign(katMaster.generateUserKeyPair(identityAlice).getPrivate(), new TestRandomBigInteger(256,
            Hex.decode("00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE")));   // r
        katSigner.update(message);
        isTrue("SM9 JCE signs to the GM/T 0044.5 KAT signature", Arrays.areEqual(katSig, katSigner.sign()));

        // 5. KeyFactory round-trips the signature master keys through X.509 / PKCS#8
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory sign master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(masterPair.getPrivate().getEncoded()));
        isTrue("SM9 KeyFactory sign master private round-trip",
            Arrays.areEqual(priv2.getEncoded(), masterPair.getPrivate().getEncoded()));

        // 6. no AlgorithmParameterSpec is accepted (a master key for verification is refused in
        //    rejectedInitTest)
        try
        {
            Signature bad = Signature.getInstance("SM9", "BC");
            bad.initVerify(masterPub.getUserPublicKey(identityAlice));
            bad.setParameter(new java.security.spec.AlgorithmParameterSpec()
            {
            });
            fail("SM9 accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }

        // 7. the sign private keys honour the Destroyable contract - on a master pair of the test's
        //    own, as the master key is destroyed
        KeyPairGenerator ownGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        ownGen.initialize(256, new SecureRandom());
        destroyTest(ownGen.generateKeyPair(), identityAlice);

        // 8. a stored user private key round-trips through the KeyFactory with only its encoding and
        //    the published master public key
        userKeySpecRoundTrip(kf, masterPub, alice.getPrivate(), identityAlice, message);

        // 9. only the encoding sign() produces is taken: a signature that does not decode is simply not
        //    valid, and a third party cannot turn a valid signature into a second byte string that
        //    verifies. Three variants carry exactly the genuine h || S - a non-minimal length, and h and
        //    S trading a byte across their boundary either way, which SM9Signature does not parse as it
        //    holds h and S to their sizes - and one the same point S in its hybrid form.
        SM9Signature parsed = SM9Signature.getInstance(sig);
        byte[] h = parsed.getH();
        byte[] s = parsed.getS();
        byte[] components = Arrays.concatenate(h, s);
        isTrue("SM9 signature uses the short length form", sig[1] == sig.length - 2);
        byte[] longLength = Arrays.concatenate(new byte[]{ sig[0], (byte)0x81 }, Arrays.copyOfRange(sig, 1, sig.length));
        byte[] shortH = new DERSequence(new DEROctetString(Arrays.copyOfRange(h, 0, 31)),
            new DERBitString(Arrays.prepend(s, h[31]))).getEncoded(ASN1Encoding.DER);
        byte[] longH = new DERSequence(new DEROctetString(Arrays.append(h, s[0])),
            new DERBitString(Arrays.copyOfRange(s, 1, s.length))).getEncoded(ASN1Encoding.DER);
        isTrue("non-minimal length parses to the same components", Arrays.areEqual(components,
            Arrays.concatenate(SM9Signature.getInstance(longLength).getH(), SM9Signature.getInstance(longLength).getS())));
        isTrue("short h does not parse", !parses(shortH));
        isTrue("long h does not parse", !parses(longH));
        byte[] hybridS = Arrays.clone(s);
        hybridS[0] = (byte)(((s[64] & 1) == 0) ? 0x06 : 0x07);
        byte[] hybrid = new SM9Signature(h, hybridS).getEncoded(ASN1Encoding.DER);

        Signature strict = Signature.getInstance("SM9", "BC");
        strict.initVerify(masterPub.getUserPublicKey(identityAlice));
        rejectsEncoding(strict, message, new byte[]{ 1, 2, 3 }, sig, "an undecodable signature");
        rejectsEncoding(strict, message, longLength, sig, "a non-minimal length");
        rejectsEncoding(strict, message, shortH, sig, "h one byte short with S carrying its last byte");
        rejectsEncoding(strict, message, longH, sig, "h one byte long carrying S's 0x04");
        rejectsEncoding(strict, message, hybrid, sig, "S in hybrid form");

        // 10. a master key serializes through its encoding; one that no longer decodes keeps the cause
        serializationTest(masterPair.getPublic());

        // 11. the SecureRandom a caller hands initSign is the one the nonce is drawn from
        callerRandomIsUsed(alice.getPrivate(), message);

        // 12. an init that is refused leaves the object uninitialised, not keyed as before
        rejectedInitTest(masterPair, alice, identityAlice, message);
    }

    /**
     * java.security.Signature records an init only once it has succeeded, so after a refused one it
     * still passes update(), sign() and verify() to the SPI. The SPI, like SM9Signer, is left
     * uninitialised by a refused init: those calls refuse with a SignatureException until an init
     * succeeds, and the message given before the refused init goes with it.
     */
    private void rejectedInitTest(KeyPair masterPair, KeyPair alice, byte[] identityAlice, byte[] message)
        throws Exception
    {
        PublicKey alicePub = ((SM9SigMasterPublicKey)masterPair.getPublic()).getUserPublicKey(identityAlice);
        PrivateKey destroyed = ((SM9SigMasterPrivateKey)masterPair.getPrivate()).generateUserKeyPair(identityAlice).getPrivate();
        ((javax.security.auth.Destroyable)destroyed).destroy();

        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(alice.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        String[] refusals = {
            "SM9 signing requires the user private key from SM9SigMasterPrivateKey.generateUserKeyPair()",
            "key destroyed",
            "SM9 verification requires the signer's public key from SM9SigMasterPublicKey.getUserPublicKey()" };
        for (int signing = 0; signing != 2; signing++)
        {
            for (int i = 0; i != refusals.length; i++)
            {
                Signature s = Signature.getInstance("SM9", "BC");
                if (signing == 1)
                {
                    s.initSign(alice.getPrivate());
                }
                else
                {
                    s.initVerify(alicePub);
                }
                s.update(message);
                try
                {
                    if (i == 0)
                    {
                        s.initSign(masterPair.getPrivate());
                    }
                    else if (i == 1)
                    {
                        s.initSign(destroyed);
                    }
                    else
                    {
                        s.initVerify(masterPair.getPublic());
                    }
                    fail("Signature.SM9 took a key it should refuse (" + i + ")");
                }
                catch (InvalidKeyException e)
                {
                    isTrue("Signature.SM9 refuses key " + i + " with: " + e.getMessage(), refusals[i].equals(e.getMessage()));
                }

                // Signature still takes itself as initialised, so each call reaches the SPI
                String after = "refusal " + i + " after an init for " + ((signing == 1) ? "signing" : "verification");
                try
                {
                    s.update((byte)0x01);
                    fail("Signature.SM9 took a byte after " + after);
                }
                catch (SignatureException e)
                {
                    isTrue("SM9 signature not initialised".equals(e.getMessage()));
                }
                try
                {
                    s.update(message);
                    fail("Signature.SM9 took a message after " + after);
                }
                catch (SignatureException e)
                {
                    isTrue("SM9 signature not initialised".equals(e.getMessage()));
                }
                try
                {
                    if (signing == 1)
                    {
                        s.sign();
                        fail("Signature.SM9 signed after " + after);
                    }
                    else
                    {
                        s.verify(sig);
                        fail("Signature.SM9 verified after " + after);
                    }
                }
                catch (SignatureException e)
                {
                    isTrue("SM9 signature not initialised".equals(e.getMessage()));
                }

                // inits that succeed after it serve as on an object never refused, over the message
                // given after them alone: the object signs, and then checks what it signed
                s.initSign(alice.getPrivate());
                s.update(message);
                byte[] again = s.sign();
                s.initVerify(alicePub);
                s.update(message);
                isTrue("Signature.SM9 signs and verifies after " + after, s.verify(again));
            }
        }

        // the message given before a refused init goes from the lightweight signer the SPI drives;
        // Signature does not hand out its SPI, so the SPI is driven directly
        Class spiClass = org.bouncycastle.jcajce.provider.asymmetric.sm9.SignatureSpi.class;
        Object spi = spiClass.getConstructor(new Class[0]).newInstance(new Object[0]);
        Method initSign = declared(spiClass, "engineInitSign", new Class[]{ PrivateKey.class });
        Method initVerify = declared(spiClass, "engineInitVerify", new Class[]{ PublicKey.class });
        Method update = declared(spiClass, "engineUpdate", new Class[]{ byte[].class, int.class, int.class });
        SM9Signer lightweight = (SM9Signer)declaredField(spiClass, "signer").get(spi);
        Object[] data = new Object[]{ message, Integers.valueOf(0), Integers.valueOf(message.length) };
        Object[][] refused = { { initSign, masterPair.getPrivate() }, { initVerify, masterPair.getPublic() } };
        for (int i = 0; i != refused.length; i++)
        {
            initSign.invoke(spi, new Object[]{ alice.getPrivate() });
            update.invoke(spi, data);
            isTrue("the signer holds the message given it", !holdsNothing(lightweight));
            try
            {
                ((Method)refused[i][0]).invoke(spi, new Object[]{ refused[i][1] });
                fail("Signature.SM9 took a master key (" + i + ")");
            }
            catch (InvocationTargetException e)
            {
                isTrue("a master key is refused (" + i + ")", e.getTargetException() instanceof InvalidKeyException);
            }
            isTrue("a refused init drops the message given before it (" + i + ")", holdsNothing(lightweight));
        }
    }

    /**
     * Whether an SM9Signer's digest holds H2's prefix 0x02 and nothing else: the words of the block
     * it is filling and of the last it compressed, and that block's expansion, all zero.
     */
    private static boolean holdsNothing(SM9Signer signer)
        throws Exception
    {
        Object digest = declaredField(SM9Signer.class, "digest").get(signer);
        int[] words = (int[])declaredField(SM3Digest.class, "inwords").get(digest);
        int[] expansion = (int[])declaredField(SM3Digest.class, "W").get(digest);
        byte[] partial = (byte[])declaredField(GeneralDigest.class, "xBuf").get(digest);
        return Nat.isZero(words.length, words) && Nat.isZero(expansion.length, expansion)
            && partial[0] == 0x02 && Arrays.areAllZeroes(partial, 1, partial.length - 1);
    }

    private static Method declared(Class c, String name, Class[] parameterTypes)
        throws Exception
    {
        Method m = c.getDeclaredMethod(name, parameterTypes);
        m.setAccessible(true);
        return m;
    }

    private static Field declaredField(Class c, String name)
        throws Exception
    {
        Field f = c.getDeclaredField(name);
        f.setAccessible(true);
        return f;
    }

    /**
     * The nonce is drawn from the SecureRandom handed to initSign(key, random), and a later
     * initSign(key) negates that call, as Signature's javadoc says - java.security.SignatureSpi keeps
     * the random in a field nothing resets, so the SPI must not go on reading it.
     */
    private void callerRandomIsUsed(PrivateKey key, byte[] message)
        throws Exception
    {
        final int[] draws = new int[1];
        SecureRandom counting = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                draws[0]++;
                super.nextBytes(bytes);
            }
        };
        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(key, counting);
        signer.update(message);
        signer.sign();
        isTrue("Signature.SM9 draws its nonce from the SecureRandom given to initSign", draws[0] > 0);

        int drawn = draws[0];
        signer.initSign(key);
        signer.update(message);
        signer.sign();
        isTrue("Signature.SM9 drew from the SecureRandom of an earlier initSign", draws[0] == drawn);

        signer.initSign(key, counting);
        signer.update(message);
        signer.sign();
        isTrue("Signature.SM9 draws from the SecureRandom given to a further initSign", draws[0] > drawn);
    }

    private void serializationTest(PublicKey masterPublic)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(masterPublic);
        oOut.close();
        byte[] stream = bOut.toByteArray();

        PublicKey restored = (PublicKey)new ObjectInputStream(new ByteArrayInputStream(stream)).readObject();
        isTrue("SM9 sign master public key serialization round-trip",
            Arrays.areEqual(masterPublic.getEncoded(), restored.getEncoded()));

        // the stream carries the X.509 encoding verbatim; replace the 0x04 opening the 129-byte G2 point
        byte[] encoding = masterPublic.getEncoded();
        int at = Strings.fromByteArray(stream).indexOf(Strings.fromByteArray(encoding));
        isTrue("serialized SM9 key carries its X.509 encoding", at >= 0);
        stream[at + encoding.length - 129] = 0x05;
        try
        {
            new ObjectInputStream(new ByteArrayInputStream(stream)).readObject();
            fail("SM9 master public key deserialized from a corrupted encoding");
        }
        catch (InvalidObjectException e)
        {
            isTrue("SM9 key deserialization failure keeps its cause", e.getCause() instanceof InvalidKeySpecException);
        }
    }

    private static boolean parses(byte[] encoding)
    {
        try
        {
            SM9Signature.getInstance(encoding);
            return true;
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }
    }

    /**
     * Checks that verify() refuses the given bytes and that the same object then verifies the genuine
     * signature over the message given afresh, which shows the refused call used up the message given
     * for it. performTest makes this check after each refusal rather than once at the end: its last
     * byte string gets as far as the lightweight signer, which clears the message itself, so a single
     * check at the end would pass even if the earlier refusals left the message behind.
     */
    private void rejectsEncoding(Signature verifier, byte[] message, byte[] encoding, byte[] genuine, String label)
        throws Exception
    {
        verifier.update(message);
        isTrue("SM9 JCE rejects " + label, !verifier.verify(encoding));
        verifier.update(message);
        isTrue("SM9 JCE verifies after rejecting " + label, verifier.verify(genuine));
    }

    /**
     * A user's signature private key does not carry the master public key it signs with, so it is
     * rebuilt from its PKCS#8 encoding through SM9SigUserPrivateKeySpec, which supplies that context -
     * the published master public key, never the master private key.
     */
    private void userKeySpecRoundTrip(KeyFactory kf, SM9SigMasterPublicKey masterPub,
                                      PrivateKey aliceKey, byte[] identityAlice, byte[] message)
        throws Exception
    {
        byte[] stored = aliceKey.getEncoded();

        PrivateKey rebuilt = kf.generatePrivate(new SM9SigUserPrivateKeySpec(stored, masterPub, identityAlice));
        isTrue("SM9 user private key spec round-trip", Arrays.areEqual(stored, rebuilt.getEncoded()));
        isTrue("SM9 spec-rebuilt user key identity",
            Arrays.areEqual(identityAlice, ((SM9SigUserPrivateKey)rebuilt).getIdentity()));

        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(rebuilt);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SM9", "BC");
        verifier.initVerify(masterPub.getUserPublicKey(identityAlice));
        verifier.update(message);
        isTrue("SM9 signature from a spec-rebuilt user key verifies", verifier.verify(sig));

        // the factory hands the same spec back for a user key
        SM9SigUserPrivateKeySpec roundTripSpec = (SM9SigUserPrivateKeySpec)kf.getKeySpec(
            aliceKey, SM9SigUserPrivateKeySpec.class);
        isTrue("SM9 getKeySpec round-trip encoding", Arrays.areEqual(stored, roundTripSpec.getEncoded()));
        isTrue("SM9 getKeySpec round-trip master public key",
            Arrays.areEqual(masterPub.getEncoded(), roundTripSpec.getMasterPublicKey().getEncoded()));
        isTrue("SM9 getKeySpec round-trip identity", Arrays.areEqual(identityAlice, roundTripSpec.getIdentity()));
    }

    private void destroyTest(KeyPair masterPair, byte[] identityAlice)
        throws Exception
    {
        SM9SigMasterPrivateKey masterPriv = (SM9SigMasterPrivateKey)masterPair.getPrivate();
        PrivateKey aliceKey = masterPriv.generateUserKeyPair(identityAlice).getPrivate();

        // a destroyed user signing key gives out neither its encoding nor its identity, and is
        // refused for signing at init, as the other signature SPIs refuse a destroyed key
        destroyAndCheck("sign user key", aliceKey);
        try
        {
            ((SM9SigUserPrivateKey)aliceKey).getIdentity();
            fail("destroyed sign user key still returns its identity");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }
        Signature signer = Signature.getInstance("SM9", "BC");
        try
        {
            signer.initSign(aliceKey);
            fail("destroyed sign user key still taken for signing");
        }
        catch (InvalidKeyException e)
        {
            isTrue("key destroyed rejection", "key destroyed".equals(e.getMessage()));
        }

        // a destroyed master private key neither encodes, derives user keys nor serializes; the
        // published master public key (verification side) is unaffected
        destroyAndCheck("sign master key", masterPriv);
        try
        {
            masterPriv.generateUserKeyPair(identityAlice);
            fail("destroyed sign master key still generates user keys");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }
        try
        {
            new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(masterPriv);
            fail("destroyed sign master key still serializes");
        }
        catch (NotSerializableException e)
        {
            // expected
        }
        isTrue("verification side unaffected by master destroy", masterPair.getPublic().getEncoded() != null);
    }

    /**
     * Destroy key, checking isDestroyed() before and after, and that getEncoded() then refuses.
     */
    private void destroyAndCheck(String label, PrivateKey key)
        throws Exception
    {
        javax.security.auth.Destroyable destroyable = (javax.security.auth.Destroyable)key;
        isTrue(label + " not destroyed yet", !destroyable.isDestroyed());
        destroyable.destroy();
        isTrue(label + " destroyed", destroyable.isDestroyed());
        try
        {
            key.getEncoded();
            fail("destroyed " + label + " still encodes");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9SignatureTest());
    }
}
