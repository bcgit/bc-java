package org.bouncycastle.openpgp.api.test;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test: {@link OpenPGPCertificate} must derive a subkey's expiration only from a
 * cryptographically valid binding signature. Appending a forged subkey-binding signature (stamped
 * with the primary's issuer key ID but signed by an unrelated key) that advertises
 * KeyExpirationTime = 0 ("never expires") and a later creation time must not override the genuine
 * expiry. See the corresponding fix in OpenPGPComponentKey.getKeyExpirationDateAt.
 */
public class OpenPGPSubkeyExpiryForgeryTest
    extends SimpleTest
{
    public String getName()
    {
        return "OpenPGPSubkeyExpiryForgeryTest";
    }

    public void performTest()
        throws Exception
    {
        char[] pass = "test".toCharArray();

        // Put the key and genuine binding in the past so the forged binding can be dated later
        // than the genuine one yet still before "now" (the evaluation time).
        long nowSec = System.currentTimeMillis() / 1000L;
        Date keyTime = new Date(1000L * (nowSec - 3600));
        Date genuineBindingTime = new Date(1000L * (nowSec - 3600));
        Date forgedBindingTime = new Date(1000L * (nowSec - 1800));
        long genuineExpiry = 86400L * 30; // 30 days

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);

        PGPKeyPair master = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), keyTime);
        PGPKeyPair sub = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), keyTime);
        PGPKeyPair attacker = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), keyTime);

        PGPDigestCalculator sha1 = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPSignatureSubpacketGenerator masterSubs = new PGPSignatureSubpacketGenerator();
        masterSubs.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, "Victim <victim@example.com>",
            sha1, masterSubs.generate(), null,
            new JcaPGPContentSignerBuilder(master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(pass));

        PGPSignatureSubpacketGenerator subSubs = new PGPSignatureSubpacketGenerator();
        subSubs.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        subSubs.setKeyExpirationTime(true, genuineExpiry);
        subSubs.setSignatureCreationTime(true, genuineBindingTime);
        gen.addSubKey(sub, subSubs.generate(), null);

        PGPPublicKeyRing ring = gen.generatePublicKeyRing();

        Date genuine = subkeyExpiry(new OpenPGPCertificate(ring));
        isTrue("test setup: genuine subkey expiry should be reported", genuine != null);

        // Forge a subkey-binding signature: signed with the attacker key, but stamped with the
        // real primary's issuer key ID, KeyExpirationTime = 0 (never expires), dated later.
        PGPPublicKey masterPub = ring.getPublicKey();
        PGPPublicKey subPub = null;
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey k = it.next();
            if (!k.isMasterKey())
            {
                subPub = k;
            }
        }

        PGPSignatureGenerator forge = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(attacker.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            attacker.getPublicKey());
        forge.init(PGPSignature.SUBKEY_BINDING, attacker.getPrivateKey());
        PGPSignatureSubpacketGenerator forged = new PGPSignatureSubpacketGenerator();
        forged.setKeyExpirationTime(true, 0);
        forged.setSignatureCreationTime(true, forgedBindingTime);
        forged.setIssuerKeyID(false, masterPub.getKeyID());
        forge.setHashedSubpackets(forged.generate());
        PGPSignature forgedSig = forge.generateCertification(masterPub, subPub);

        PGPPublicKey tamperedSub = PGPPublicKey.addCertification(subPub, forgedSig);
        PGPPublicKeyRing tamperedRing = PGPPublicKeyRing.insertPublicKey(
            PGPPublicKeyRing.removePublicKey(ring, subPub), tamperedSub);
        tamperedRing = new PGPPublicKeyRing(tamperedRing.getEncoded(), new JcaKeyFingerprintCalculator());

        Date afterTamper = subkeyExpiry(new OpenPGPCertificate(tamperedRing));
        isTrue("forged never-expires binding must not override genuine expiry (got never-expires)",
            afterTamper != null);
        isEquals("genuine subkey expiry must be preserved after forged binding appended",
            genuine, afterTamper);
    }

    private static Date subkeyExpiry(OpenPGPCertificate cert)
    {
        for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> it = cert.getKeys().iterator(); it.hasNext(); )
        {
            OpenPGPCertificate.OpenPGPComponentKey k = it.next();
            if (!k.isPrimaryKey())
            {
                return k.getKeyExpirationDate();
            }
        }
        return null;
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenPGPSubkeyExpiryForgeryTest());
    }
}
