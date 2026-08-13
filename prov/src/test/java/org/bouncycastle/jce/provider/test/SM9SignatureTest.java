package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.gm.SM9Signature;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserKeyGenerator;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPublicKey;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

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
        byte[] identityAlice = "Alice".getBytes("US-ASCII");
        byte[] message = "Chinese IBS standard".getBytes("US-ASCII");

        // 1. generate a master key pair, derive Alice's key pair, sign and verify -
        //    the verifier forms Alice's public key from the master public key + identity
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        KeyPair masterPair = kpGen.generateKeyPair();
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

        // the user keys derive their identity (and, for the public key, the master public
        // key) directly, rather than a caller having to track them separately
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

        // 3. a zero-length message signs and verifies (the signer's l = 0 retry is a
        //    scalar test, so - unlike the SM9 stream cipher's K1 check - an empty
        //    message is well-defined)
        Signature emptySigner = Signature.getInstance("SM9", "BC");
        emptySigner.initSign(alice.getPrivate());
        byte[] emptySig = emptySigner.sign();

        Signature emptyVerifier = Signature.getInstance("SM9", "BC");
        emptyVerifier.initVerify(masterPub.getUserPublicKey(identityAlice));
        isTrue("SM9 JCE zero-length message round-trip", emptyVerifier.verify(emptySig));

        // 4. verify the official GM/T 0044.5 Annex A signature through the provider;
        //    the KAT master key is reconstructed through the public KeyFactory / PKCS#8
        //    path and the KAT public key derived from it
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

        // 5. KeyFactory round-trips the signature master keys through X.509 / PKCS#8
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory sign master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(masterPair.getPrivate().getEncoded()));
        isTrue("SM9 KeyFactory sign master private round-trip",
            Arrays.areEqual(priv2.getEncoded(), masterPair.getPrivate().getEncoded()));

        // 6. guards: verification takes the signer's public key, not the master key,
        //    and no AlgorithmParameterSpec is accepted
        try
        {
            Signature bad = Signature.getInstance("SM9", "BC");
            bad.initVerify(masterPair.getPublic());
            fail("SM9 accepted a master public key for verification");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
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

        // 7. the sign private keys honour the Destroyable contract
        destroyTest(masterPair, identityAlice, message);

        // 8. a stored user private key round-trips through the KeyFactory without the master
        //    private key, using only the encoding and the published master public key
        userKeySpecRoundTrip(kf, masterPub, alice.getPrivate(), identityAlice, message);
    }

    /**
     * A user's signature private key does not carry the master public key it needs to sign
     * with, so it cannot be rebuilt from its bare PKCS#8 encoding the way a master key can -
     * SM9SigUserPrivateKeySpec supplies that context, letting a stored user key be
     * reconstituted with only the published master public key, never the master private key.
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

    private void destroyTest(KeyPair masterPair, byte[] identityAlice, byte[] message)
        throws Exception
    {
        SM9SigMasterPrivateKey masterPriv = (SM9SigMasterPrivateKey)masterPair.getPrivate();
        KeyPair alice = masterPriv.generateUserKeyPair(identityAlice);
        PrivateKey aliceKey = alice.getPrivate();

        // destroying the user signing key stops signing and encoding
        isTrue("sign user key not destroyed yet", !((javax.security.auth.Destroyable)aliceKey).isDestroyed());
        ((javax.security.auth.Destroyable)aliceKey).destroy();
        isTrue("sign user key destroyed", ((javax.security.auth.Destroyable)aliceKey).isDestroyed());

        try
        {
            aliceKey.getEncoded();
            fail("destroyed sign user key still encodes");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

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
            signer.update(message);
            signer.sign();
            fail("destroyed sign user key still signs");
        }
        catch (Exception e)
        {
            // the IllegalStateException may surface directly or wrapped by the JCA
            isTrue("key destroyed rejection",
                e instanceof IllegalStateException || e.getCause() instanceof IllegalStateException);
        }

        // destroying the master private key stops key generation and encoding; the
        // published master public key (verification side) is unaffected
        javax.security.auth.Destroyable master = (javax.security.auth.Destroyable)masterPriv;
        isTrue("sign master key not destroyed yet", !master.isDestroyed());
        master.destroy();
        isTrue("sign master key destroyed", master.isDestroyed());

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
            masterPriv.getEncoded();
            fail("destroyed sign master key still encodes");
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

        isTrue("verification side unaffected by master destroy",
            masterPair.getPublic().getEncoded() != null);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9SignatureTest());
    }
}
