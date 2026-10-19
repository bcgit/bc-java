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
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
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

    private final OpenPGPApi api = new BcOpenPGPApi();

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

        OpenPGPKey key = api.generateKey(version, new Date(System.currentTimeMillis() - 86400000L))
            .classicKey(USER_ID)
            .build();
        PGPPublicKeyRing trusted = key.toCertificate().getPGPPublicKeyRing();
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

        // the same through the high-level API
        OpenPGPCertificate cert = OpenPGPCertificate.join(
            OpenPGPCertificate.join(parse(trusted), parse(with(trusted, target, relabelled))),
            parse(with(trusted, target, genuine)));
        isEquals("genuine " + label + " must be stored by OpenPGPCertificate.join after a relabelled copy",
            1, count(cert.getPGPPublicKeyRing(), target, genuine));

        isTrue("merging must leave the " + label + " test's original ring unchanged",
            Arrays.areEqual(trustedEncoding, trusted.getEncoded()));
    }

    private void sameSignatureIsStillMerged(int version)
        throws Exception
    {
        OpenPGPKey key = api.generateKey(version, new Date(System.currentTimeMillis() - 86400000L))
            .classicKey(USER_ID)
            .build();
        PGPPublicKeyRing trusted = key.toCertificate().getPGPPublicKeyRing();

        PGPSignature genuine = revocation(key, KEY);
        PGPPublicKeyRing withRevocation = with(trusted, KEY, genuine);

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(withRevocation, withRevocation);
        isEquals("v" + version + " signature merged with itself must be stored once",
            1, count(merged, KEY, genuine));
        isEquals("v" + version + " signature merged with itself must leave the other signatures alone",
            signatureCount(withRevocation.getPublicKey()), signatureCount(merged.getPublicKey()));
    }

    private PGPSignature revocation(OpenPGPKey key, int target)
        throws PGPException
    {
        PGPPublicKey primary = key.getPrimaryKey().getPGPPublicKey();
        PGPPrivateKey privateKey = key.getPrimarySecretKey().unlock().getKeyPair().getPrivateKey();

        int type = target == KEY ? PGPSignature.KEY_REVOCATION
            : target == SUBKEY ? PGPSignature.SUBKEY_REVOCATION : PGPSignature.CERTIFICATION_REVOCATION;

        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            api.getImplementation().pgpContentSignerBuilder(primary.getAlgorithm(), HashAlgorithmTags.SHA512),
            primary);
        gen.init(type, privateKey);

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
            return gen.generateCertification(primary, subkey(key.toCertificate().getPGPPublicKeyRing()));
        }
        return gen.generateCertification(USER_ID, primary);
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
        signature.init(api.getImplementation().pgpContentVerifierBuilderProvider(), primary);
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

    private int count(PGPPublicKeyRing ring, int target, PGPSignature signature)
        throws IOException
    {
        PGPPublicKey key = target == SUBKEY ? subkey(ring) : ring.getPublicKey();
        Iterator<PGPSignature> it = target == USER_ID_TARGET
            ? key.getSignaturesForID(USER_ID)
            : key.getSignatures();

        byte[] encoding = signature.getEncoded();
        int count = 0;
        while (it.hasNext())
        {
            if (Arrays.areEqual(encoding, it.next().getEncoded()))
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

    private boolean isRevoked(PGPPublicKeyRing ring, int target)
        throws IOException
    {
        OpenPGPCertificate cert = parse(ring);
        Date now = new Date();
        if (target == KEY)
        {
            return !cert.getPrimaryKey().isBoundAt(now);
        }
        if (target == SUBKEY)
        {
            return cert.getEncryptionKeys(now).isEmpty();
        }
        return cert.getValidUserIds(now).isEmpty();
    }

    private OpenPGPCertificate parse(PGPPublicKeyRing ring)
        throws IOException
    {
        // re-parse from the wire, as a relying party would
        return api.readKeyOrCertificate().parseCertificate(ring.getEncoded());
    }

    private PGPPublicKey subkey(PGPPublicKeyRing ring)
    {
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey key = it.next();
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
