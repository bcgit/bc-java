package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test: merging certificates must not let an invalid copy of a signature displace the genuine one.
 * <p>
 * {@link PGPPublicKeyRing#join(PGPPublicKeyRing, PGPPublicKeyRing)} treated two signatures as copies of one
 * another when their signature values matched, and kept the copy it already held. A copy of a genuine
 * revocation with its signature type and hashed creation time rewritten and the signature value left as it
 * was no longer verifies, but matched - so once it had been merged, the genuine revocation arriving later, or
 * after it in the same update, was discarded as its duplicate and the key, subkey or user ID stayed usable.
 * Two copies of one signature may only differ in their unhashed area, which is what the merge now requires.
 * <p>
 * Two further merge defects are covered on the way: the merge added to the first ring's own user ID signature
 * lists, so joining changed the ring passed in, and merging two copies of a version 4 signature whose value is
 * a native encoding (Ed25519) rather than MPIs lost that value, leaving a ring that could not be encoded.
 */
public class PGPSignatureMergeTest
    extends SimpleTest
{
    private static final String USER_ID = "Alice <alice@example.com>";

    private static final int KEY = 0;
    private static final int SUBKEY = 1;
    private static final int USER_ID_TARGET = 2;

    public String getName()
    {
        return "PGPSignatureMergeTest";
    }

    public void performTest()
        throws Exception
    {
        int[] versions = new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6};
        int[] targets = new int[]{KEY, SUBKEY, USER_ID_TARGET};

        for (int i = 0; i != versions.length; i++)
        {
            for (int j = 0; j != targets.length; j++)
            {
                revocationSurvivesRelabelledCopy(versions[i], targets[j]);
            }
            sameSignatureIsStillMerged(versions[i]);
        }
    }

    private void revocationSurvivesRelabelledCopy(int version, int target)
        throws Exception
    {
        String label = "v" + version + " " + new String[]{"key", "subkey", "user ID"}[target] + " revocation";

        PGPSecretKeyRing key = generateKey(version);
        PGPPublicKeyRing trusted = key.toCertificate();
        byte[] trustedEncoding = trusted.getEncoded();

        PGPSignature genuine = revocation(key, target);
        PGPSignature relabelled = relabel(genuine);

        isTrue("test setup: " + label + " should verify", verifies(trusted, genuine, target));
        isTrue("test setup: relabelled " + label + " should not verify", !verifies(trusted, relabelled, target));
        isTrue("test setup: relabelled " + label + " should keep the signature value",
            PGPSignature.isSignatureEncodingEqual(genuine, relabelled));

        // control: the genuine revocation first
        PGPPublicKeyRing control = PGPPublicKeyRing.join(trusted, with(trusted, target, genuine, relabelled));
        isEquals("genuine " + label + " must be stored when it arrives first", 1, count(control, target, genuine));
        isTrue("genuine " + label + " must take effect when it arrives first", isRevoked(control, target));

        // the invalid copy in one update, the genuine revocation in the next
        PGPPublicKeyRing twoUpdates = PGPPublicKeyRing.join(
            PGPPublicKeyRing.join(trusted, with(trusted, target, relabelled)),
            with(trusted, target, genuine));
        isEquals("genuine " + label + " must be stored after a relabelled copy was merged",
            1, count(twoUpdates, target, genuine));
        isTrue("genuine " + label + " must take effect after a relabelled copy was merged",
            isRevoked(twoUpdates, target));

        // both in one update, the invalid copy first
        PGPPublicKeyRing oneUpdate = PGPPublicKeyRing.join(trusted, with(trusted, target, relabelled, genuine));
        isEquals("genuine " + label + " must be stored behind a relabelled copy in the same update",
            1, count(oneUpdate, target, genuine));
        isTrue("genuine " + label + " must take effect behind a relabelled copy in the same update",
            isRevoked(oneUpdate, target));

        isTrue("merging must leave the " + label + " test's original ring unchanged",
            Arrays.areEqual(trustedEncoding, trusted.getEncoded()));
    }

    private void sameSignatureIsStillMerged(int version)
        throws Exception
    {
        PGPSecretKeyRing key = generateKey(version);
        PGPPublicKeyRing trusted = key.toCertificate();

        PGPSignature genuine = revocation(key, KEY);
        PGPPublicKeyRing withRevocation = with(trusted, KEY, genuine);

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(withRevocation, withRevocation);
        isEquals("v" + version + " signature merged with itself must be stored once",
            1, count(merged, KEY, genuine));
        isEquals("v" + version + " signature merged with itself must leave the other signatures alone",
            signatureCount(withRevocation.getPublicKey()), signatureCount(merged.getPublicKey()));
    }

    /**
     * Generate an Ed25519 primary key carrying the user ID, with an X25519 encryption subkey, created a day ago.
     */
    private PGPSecretKeyRing generateKey(int version)
        throws PGPException
    {
        Date creationTime = new Date(System.currentTimeMillis() - 86400000L);
        PGPKeyPairGenerator kpGen = new BcPGPKeyPairGeneratorProvider().get(version, creationTime);
        PGPKeyPair primary = kpGen.generatePrimaryKey();

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setIssuerFingerprint(true, primary.getPublicKey());
        hashed.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary, USER_ID,
            new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), hashed.generate(), null,
            new BcPGPContentSignerBuilder(primary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512), null);

        hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setIssuerFingerprint(true, primary.getPublicKey());
        hashed.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        gen.addSubKey(kpGen.generateEncryptionSubkey(), hashed.generate(), null);

        return gen.generateSecretKeyRing();
    }

    private PGPSignature revocation(PGPSecretKeyRing key, int target)
        throws PGPException
    {
        PGPPublicKey primary = key.getPublicKey();
        PGPPrivateKey privateKey = key.getSecretKey().extractPrivateKey(null);

        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(primary.getAlgorithm(), HashAlgorithmTags.SHA512), primary);
        gen.init(revocationType(target), privateKey);

        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setSignatureCreationTime(true, new Date());
        subpackets.setIssuerFingerprint(true, primary);
        subpackets.setRevocationReason(true,
            target == USER_ID_TARGET ? RevocationReasonTags.USER_NO_LONGER_VALID : RevocationReasonTags.KEY_COMPROMISED,
            "");
        gen.setHashedSubpackets(subpackets.generate());

        if (target == KEY)
        {
            return gen.generateCertification(primary);
        }
        if (target == SUBKEY)
        {
            return gen.generateCertification(primary, subkey(key.toCertificate()));
        }
        return gen.generateCertification(USER_ID, primary);
    }

    private static int revocationType(int target)
    {
        return target == KEY ? PGPSignature.KEY_REVOCATION
            : target == SUBKEY ? PGPSignature.SUBKEY_REVOCATION : PGPSignature.CERTIFICATION_REVOCATION;
    }

    /**
     * Return a copy of the signature with its type changed to the corresponding certification and its hashed
     * creation time moved on a second, but the signature value, and salt, left as they were.
     */
    private PGPSignature relabel(PGPSignature signature)
        throws IOException
    {
        SignaturePacket p = (SignaturePacket)new BCPGInputStream(
            new ByteArrayInputStream(signature.getEncoded())).readPacket();

        int type = p.getSignatureType() == PGPSignature.KEY_REVOCATION ? PGPSignature.DIRECT_KEY
            : p.getSignatureType() == PGPSignature.SUBKEY_REVOCATION ? PGPSignature.SUBKEY_BINDING
            : PGPSignature.POSITIVE_CERTIFICATION;

        SignatureSubpacket[] hashed = p.getHashedSubPackets();
        SignatureSubpacket[] relabelled = new SignatureSubpacket[hashed.length];
        for (int i = 0; i != hashed.length; i++)
        {
            if (hashed[i].getType() == SignatureSubpacketTags.CREATION_TIME)
            {
                Date time = ((SignatureCreationTime)hashed[i]).getTime();
                relabelled[i] = new SignatureCreationTime(true, new Date(time.getTime() + 1000));
            }
            else
            {
                relabelled[i] = hashed[i];
            }
        }

        SignaturePacket copy;
        if (p.getSignature() == null)
        {
            // native signature encoding (e.g. Ed25519), with the salt for a version 6 signature
            copy = new SignaturePacket(p.getVersion(), type, p.getKeyID(), p.getKeyAlgorithm(), p.getHashAlgorithm(),
                relabelled, p.getUnhashedSubPackets(), p.getFingerPrint(), p.getSignatureBytes(), p.getSalt());
        }
        else
        {
            copy = new SignaturePacket(p.getVersion(), p.hasNewPacketFormat(), type, p.getKeyID(), p.getKeyAlgorithm(),
                p.getHashAlgorithm(), relabelled, p.getUnhashedSubPackets(), p.getFingerPrint(), p.getSignature());
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);
        copy.encode(pOut);
        pOut.close();

        return ((PGPSignatureList)new BcPGPObjectFactory(bOut.toByteArray()).nextObject()).get(0);
    }

    private boolean verifies(PGPPublicKeyRing ring, PGPSignature signature, int target)
        throws PGPException
    {
        PGPPublicKey primary = ring.getPublicKey();
        signature.init(new BcPGPContentVerifierBuilderProvider(), primary);
        if (target == KEY)
        {
            return signature.verifyCertification(primary);
        }
        if (target == SUBKEY)
        {
            return signature.verifyCertification(primary, subkey(ring));
        }
        return signature.verifyCertification(USER_ID, primary);
    }

    private PGPPublicKeyRing with(PGPPublicKeyRing ring, int target, PGPSignature first)
    {
        return with(ring, target, first, null);
    }

    /**
     * Return the ring with the given signatures, in order, attached to the target.
     */
    private PGPPublicKeyRing with(PGPPublicKeyRing ring, int target, PGPSignature first, PGPSignature second)
    {
        PGPPublicKey key = target == SUBKEY ? subkey(ring) : ring.getPublicKey();
        PGPSignature[] signatures = second == null ? new PGPSignature[]{first} : new PGPSignature[]{first, second};
        for (int i = 0; i != signatures.length; i++)
        {
            key = target == USER_ID_TARGET
                ? PGPPublicKey.addCertification(key, USER_ID, signatures[i])
                : PGPPublicKey.addCertification(key, signatures[i]);
        }
        return PGPPublicKeyRing.insertPublicKey(ring, key);
    }

    private Iterator<PGPSignature> signatures(PGPPublicKeyRing ring, int target)
    {
        PGPPublicKey key = target == SUBKEY ? subkey(ring) : ring.getPublicKey();
        return target == USER_ID_TARGET ? key.getSignaturesForID(USER_ID) : key.getSignatures();
    }

    private int count(PGPPublicKeyRing ring, int target, PGPSignature signature)
        throws IOException
    {
        Iterator<PGPSignature> it = signatures(ring, target);

        byte[] encoding = signature.getEncoded();
        int count = 0;
        while (it.hasNext())
        {
            if (Arrays.areEqual(encoding, ((PGPSignature)it.next()).getEncoded()))
            {
                count++;
            }
        }
        return count;
    }

    private int signatureCount(PGPPublicKey key)
    {
        int count = 0;
        for (Iterator<PGPSignature> it = key.getSignatures(); it.hasNext(); it.next())
        {
            count++;
        }
        return count;
    }

    /**
     * Return true if the target carries a revocation that verifies.
     */
    private boolean isRevoked(PGPPublicKeyRing ring, int target)
        throws IOException, PGPException
    {
        // re-parse from the wire, as a relying party would
        PGPPublicKeyRing parsed = new PGPPublicKeyRing(ring.getEncoded(), new BcKeyFingerprintCalculator());
        int type = revocationType(target);
        for (Iterator<PGPSignature> it = signatures(parsed, target); it.hasNext(); )
        {
            PGPSignature signature = (PGPSignature)it.next();
            if (signature.getSignatureType() == type && verifies(parsed, signature, target))
            {
                return true;
            }
        }
        return false;
    }

    private PGPPublicKey subkey(PGPPublicKeyRing ring)
    {
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey key = (PGPPublicKey)it.next();
            if (!key.isMasterKey() && key.isEncryptionKey())
            {
                return key;
            }
        }
        fail("test setup: certificate should carry an encryption subkey");
        return null;
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPSignatureMergeTest());
    }
}
