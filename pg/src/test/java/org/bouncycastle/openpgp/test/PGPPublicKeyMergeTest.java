package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for certificate merging.
 * Test vectors are taken with permission from Sequoia-PGP.
 *
 * @see <a href="https://sequoia-pgp.org">Sequoia-PGP</a>
 * @see <a href="https://gitlab.com/sequoia-pgp/sequoia/-/tree/main/openpgp/tests/data/keys">Test Vectors</a>
 */
public class PGPPublicKeyMergeTest
    extends SimpleTest
{
    private static final String CERT_1_BASE = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=2faY\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_1_ADD_UID_1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=F4ya\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_1_ADD_UID_2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "p+tU95omEWMuc1MpeLJzt6uwi3FEYQgT\n" +
        "=QO0q\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_1_ADD_UID_3 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=Q9fi\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_1_ALL_UIDS = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "GcNIp+tU95omEWMuc1MpeLJzt6uwi3FEYQgT\n" +
        "=c2Kx\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_1_ADD_SUBKEY_1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "RKo/WjxUUnqjZytHjc9FSNjc\n" +
        "=N/eW\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_1_ADD_SUBKEY_2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=zbTd\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_1_ADD_SUBKEY_3 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "4rY=\n" +
        "=K315\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_1_ALL_SUBKEYS = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=MtsI\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_1_ALL_SUBKEYS_AND_UIDS = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=NRW6\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_2_BASE = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=SEdr\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_2_SIGNS_CERT_1_BASE = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "t6uwi3FEYQgT\n" +
        "=BVz1\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_2_SIGNS_CERT_1_ALL_USER_IDS = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=e/pf\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CERT_3_SIGNS_CERT_1_BASE = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "t6uwi3FEYQgT\n" +
        "=KJlw\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String CERT_3_SIGNS_CERT_1_ALL_USER_IDS = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=UeHX\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    private static final int firstUserIdSelfSigs = 1;
    private static final int secondUserIdSelfSigs = 2;
    private static final int thirdUserIdSelfSigs = 1;

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPPublicKeyMergeTest());
    }

    @Override
    public String getName()
    {
        return "PGPPublicKeyMergeTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        cannotMergeDifferentCerts();

        duplicateUserIdIsMergedWhenReadingCert();

        mergeBaseWithItselfDoesNotChangeCert();
        mergeAllUserIdsInOrderYieldsAllUserIds();
        mergeAllUserIdsInReverseYieldsAllUserIds();
        mergeAddUserId1WithBaseYieldsUserId1();

        mergeAllSubkeysInOrderYieldsAllSubkeys();
        mergeAllSubkeysInReverseYieldsAllSubkeys();
        mergeAddSubkey1WithBaseYieldsSubkey1();

        mergeAllSubkeysAndUserIdsYieldsAllSubkeysUserIds();
        mergeAllSubkeysWithAllUserIdsYieldsAllSubkeysAndUserIds();

        // 3rd party certifications
        mergeCert2SignsBaseWithBaseYieldsCert2SignsBase();
        mergeCert2SignsAllUserIdsWithBaseYieldsCert2SignsAllUserIds();
        mergeCert3SignsBaseWithBaseYieldsCert3SignsBase();
        mergeCert3SignsAllUserIdsWithBaseYieldsCert3SignsAllUserIds();

        mergeCert2SignsBaseWithCert3SignsBase();
        mergeAllCert2AndCert3Certifications();
    }

    public void cannotMergeDifferentCerts()
        throws IOException, PGPException
    {
        PGPPublicKeyRing cert1 = readCert(CERT_1_BASE);
        PGPPublicKeyRing cert2 = readCert(CERT_2_BASE);

        try
        {
            PGPPublicKeyRing.join(cert1, cert2);
        }
        catch (IllegalArgumentException e)
        {
            // expected
            return;
        }
        fail("Cannot merge two different certificates");
    }

    /**
     * Merging a certificate with itself does not change anything.
     *
     * @throws IOException
     * @throws PGPException
     */
    public void mergeBaseWithItselfDoesNotChangeCert()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing base2 = readCert(CERT_1_BASE);

        PGPPublicKeyRing joined = PGPPublicKeyRing.join(base, base2);

        areEqual(base.getEncoded(), joined.getEncoded());
    }

    /**
     * ADD_ALL_UIDS has 4 user-ids, where 2 are equal, just with different binding sigs.
     * Those are expected to be merged together by BC.
     *
     * @throws IOException
     */
    public void duplicateUserIdIsMergedWhenReadingCert()
        throws IOException
    {
        PGPPublicKeyRing allUserIds = readCert(CERT_1_ALL_UIDS);

        isEquals(3, count((Iterator)allUserIds.getPublicKey().getUserIDs()));
        Iterator<String> userIds = allUserIds.getPublicKey().getUserIDs();
        isEquals("first user-id self-sig count; " + firstUserIdSelfSigs,
            firstUserIdSelfSigs, count((Iterator)allUserIds.getPublicKey().getSignaturesForID((String)userIds.next())));
        isEquals("second user-id self-sig count: " + secondUserIdSelfSigs,
            secondUserIdSelfSigs, count((Iterator)allUserIds.getPublicKey().getSignaturesForID((String)userIds.next())));
        isEquals("third user-id self-sig count: " + thirdUserIdSelfSigs,
            thirdUserIdSelfSigs, count((Iterator)allUserIds.getPublicKey().getSignaturesForID((String)userIds.next())));
    }

    public void mergeAllUserIdsInOrderYieldsAllUserIds()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addUserId1 = readCert(CERT_1_ADD_UID_1);
        PGPPublicKeyRing addUserId2 = readCert(CERT_1_ADD_UID_2);
        PGPPublicKeyRing addUserId3 = readCert(CERT_1_ADD_UID_3);

        PGPPublicKeyRing allUserIds = readCert(CERT_1_ALL_UIDS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(base, addUserId1);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, addUserId2);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge2, addUserId3);

        areEqual(allUserIds.getEncoded(), finalMerge.getEncoded());
    }

    public void mergeAllUserIdsInReverseYieldsAllUserIds()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addUserId1 = readCert(CERT_1_ADD_UID_1);
        PGPPublicKeyRing addUserId2 = readCert(CERT_1_ADD_UID_2);
        PGPPublicKeyRing addUserId3 = readCert(CERT_1_ADD_UID_3);

        PGPPublicKeyRing allUserIds = readCert(CERT_1_ALL_UIDS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(base, addUserId3);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, addUserId2);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge2, addUserId1);

        areEqual(allUserIds.getEncoded(), finalMerge.getEncoded());
    }

    public void mergeAddUserId1WithBaseYieldsUserId1()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addUserId1 = readCert(CERT_1_ADD_UID_1);

        PGPPublicKeyRing merge = PGPPublicKeyRing.join(addUserId1, base);

        areEqual(addUserId1.getEncoded(), merge.getEncoded());
    }

    public void mergeAllSubkeysInOrderYieldsAllSubkeys()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addSubkey1 = readCert(CERT_1_ADD_SUBKEY_1);
        PGPPublicKeyRing addSubkey2 = readCert(CERT_1_ADD_SUBKEY_2);
        PGPPublicKeyRing addSubkey3 = readCert(CERT_1_ADD_SUBKEY_3);

        PGPPublicKeyRing allSubkeys = readCert(CERT_1_ALL_SUBKEYS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(base, addSubkey1);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, addSubkey2);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge2, addSubkey3);

        areEqual(allSubkeys.getEncoded(), finalMerge.getEncoded());
    }

    public void mergeAllSubkeysInReverseYieldsAllSubkeys()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addSubkey1 = readCert(CERT_1_ADD_SUBKEY_1);
        PGPPublicKeyRing addSubkey2 = readCert(CERT_1_ADD_SUBKEY_2);
        PGPPublicKeyRing addSubkey3 = readCert(CERT_1_ADD_SUBKEY_3);

        PGPPublicKeyRing allSubkeys = readCert(CERT_1_ALL_SUBKEYS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(base, addSubkey3);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, addSubkey2);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge2, addSubkey1);

        areEqual(allSubkeys.getEncoded(), finalMerge.getEncoded());
    }

    public void mergeAddSubkey1WithBaseYieldsSubkey1()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addSubkey1 = readCert(CERT_1_ADD_SUBKEY_1);

        PGPPublicKeyRing merge = PGPPublicKeyRing.join(addSubkey1, base);

        areEqual(addSubkey1.getEncoded(), merge.getEncoded());
    }

    public void mergeAllSubkeysWithAllUserIdsYieldsAllSubkeysAndUserIds()
        throws PGPException, IOException
    {
        PGPPublicKeyRing allSubkeys = readCert(CERT_1_ALL_SUBKEYS);
        PGPPublicKeyRing allUserIds = readCert(CERT_1_ALL_UIDS);
        PGPPublicKeyRing allSubkeysAndUserIds = readCert(CERT_1_ALL_SUBKEYS_AND_UIDS);

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(allSubkeys, allUserIds);
        areEqual(allSubkeysAndUserIds.getEncoded(), merged.getEncoded());
        merged = PGPPublicKeyRing.join(allUserIds, allSubkeys);
        areEqual(allSubkeysAndUserIds.getEncoded(), merged.getEncoded());
    }

    public void mergeAllSubkeysAndUserIdsYieldsAllSubkeysUserIds()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing addUserId1 = readCert(CERT_1_ADD_UID_1);
        PGPPublicKeyRing addUserId2 = readCert(CERT_1_ADD_UID_2);
        PGPPublicKeyRing addUserId3 = readCert(CERT_1_ADD_UID_3);
        PGPPublicKeyRing addSubkey1 = readCert(CERT_1_ADD_SUBKEY_1);
        PGPPublicKeyRing addSubkey2 = readCert(CERT_1_ADD_SUBKEY_2);
        PGPPublicKeyRing addSubkey3 = readCert(CERT_1_ADD_SUBKEY_3);

        PGPPublicKeyRing allSubkeys = readCert(CERT_1_ALL_SUBKEYS_AND_UIDS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(base, addSubkey1);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, addUserId1);
        PGPPublicKeyRing merge3 = PGPPublicKeyRing.join(merge2, addSubkey3);
        PGPPublicKeyRing merge4 = PGPPublicKeyRing.join(merge3, addSubkey2);
        PGPPublicKeyRing merge5 = PGPPublicKeyRing.join(merge4, addUserId3);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge5, addUserId2);

        areEqual(allSubkeys.getEncoded(), finalMerge.getEncoded());
    }

    public void mergeCert2SignsBaseWithBaseYieldsCert2SignsBase()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing cert2SignsBase = readCert(CERT_2_SIGNS_CERT_1_BASE);

        isEquals("base has 1 user-id", 1, count((Iterator)base.getPublicKey().getUserIDs()));
        String userId = (String)base.getPublicKey().getUserIDs().next();
        isEquals("base has 1 signature on user-id", 1, count((Iterator)base.getPublicKey().getSignaturesForID((String)userId)));

        isEquals("signed cert has 1 user-id", 1, count((Iterator)cert2SignsBase.getPublicKey().getUserIDs()));
        isEquals("signed cert has 1 self-sig and 1 certification", 2, count((Iterator)cert2SignsBase.getPublicKey().getSignaturesForID((String)userId)));

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(base, cert2SignsBase);

        areEqual(cert2SignsBase.getEncoded(), merged.getEncoded());
    }

    public void mergeCert2SignsAllUserIdsWithBaseYieldsCert2SignsAllUserIds()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing cert2SignsAll = readCert(CERT_2_SIGNS_CERT_1_ALL_USER_IDS);

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(base, cert2SignsAll);

        areEqual(cert2SignsAll.getEncoded(), merged.getEncoded());
    }

    public void mergeCert3SignsBaseWithBaseYieldsCert3SignsBase()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing cert3SignsBase = readCert(CERT_3_SIGNS_CERT_1_BASE);

        isEquals("base has 1 user-id", 1, count((Iterator)base.getPublicKey().getUserIDs()));
        String userId = (String)base.getPublicKey().getUserIDs().next();
        isEquals("base has 1 signature on user-id", 1, count((Iterator)base.getPublicKey().getSignaturesForID((String)userId)));

        isEquals("signed cert has 1 user-id", 1, count((Iterator)cert3SignsBase.getPublicKey().getUserIDs()));
        isEquals("signed cert has 1 self-sig and 1 certifications", 2, count((Iterator)cert3SignsBase.getPublicKey().getSignaturesForID((String)userId)));

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(base, cert3SignsBase);

        areEqual(cert3SignsBase.getEncoded(), merged.getEncoded());
    }

    public void mergeCert3SignsAllUserIdsWithBaseYieldsCert3SignsAllUserIds()
        throws IOException, PGPException
    {
        PGPPublicKeyRing base = readCert(CERT_1_BASE);
        PGPPublicKeyRing cert3SignsAll = readCert(CERT_3_SIGNS_CERT_1_ALL_USER_IDS);

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(base, cert3SignsAll);

        areEqual(cert3SignsAll.getEncoded(), merged.getEncoded());
    }

    public void mergeCert2SignsBaseWithCert3SignsBase()
        throws PGPException, IOException
    {
        PGPPublicKeyRing cert2SignsBase = readCert(CERT_2_SIGNS_CERT_1_BASE);
        PGPPublicKeyRing cert3SignsBase = readCert(CERT_3_SIGNS_CERT_1_BASE);

        isEquals(1, count((Iterator)cert2SignsBase.getPublicKey().getUserIDs()));
        isEquals(1, count((Iterator)cert3SignsBase.getPublicKey().getUserIDs()));
        String userId = (String)cert2SignsBase.getPublicKey().getUserIDs().next();
        isEquals(2, count((Iterator)cert2SignsBase.getPublicKey().getSignaturesForID(userId)));
        isEquals(2, count((Iterator)cert3SignsBase.getPublicKey().getSignaturesForID(userId)));

        PGPPublicKeyRing merged = PGPPublicKeyRing.join(cert2SignsBase, cert3SignsBase);
        isEquals("There should now be one signature from each cert on the first user-id",
            2, count((Iterator)merged.getPublicKey().getSignaturesForID(userId)) - firstUserIdSelfSigs);
    }

    public void mergeAllCert2AndCert3Certifications()
        throws IOException, PGPException
    {
        PGPPublicKeyRing cert2SignsBase = readCert(CERT_2_SIGNS_CERT_1_BASE);
        PGPPublicKeyRing cert2SignsAll = readCert(CERT_2_SIGNS_CERT_1_ALL_USER_IDS);
        PGPPublicKeyRing cert3SignsBase = readCert(CERT_3_SIGNS_CERT_1_BASE);
        PGPPublicKeyRing cert3SignsAll = readCert(CERT_3_SIGNS_CERT_1_ALL_USER_IDS);

        PGPPublicKeyRing merge1 = PGPPublicKeyRing.join(cert2SignsBase, cert2SignsAll);
        PGPPublicKeyRing merge2 = PGPPublicKeyRing.join(merge1, cert3SignsAll);
        PGPPublicKeyRing finalMerge = PGPPublicKeyRing.join(merge2, cert3SignsBase);

        Iterator<String> userIds = finalMerge.getPublicKey().getUserIDs();
        isEquals("there should be two certifications from each cert on the first UID",
            4, count((Iterator)finalMerge.getPublicKey().getSignaturesForID((String)userIds.next())) - firstUserIdSelfSigs);
        isEquals("there should be one certification from each cert on the second UID",
            2, count((Iterator)finalMerge.getPublicKey().getSignaturesForID((String)userIds.next())) - secondUserIdSelfSigs);
        isEquals("there should be one certification from each cert on the third UID",
            2, count((Iterator)finalMerge.getPublicKey().getSignaturesForID((String)userIds.next())) - thirdUserIdSelfSigs);
    }

    private PGPPublicKeyRing readCert(String encodedCertificate)
        throws IOException
    {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(Strings.toByteArray(encodedCertificate));
        ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);

        return new PGPPublicKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }

    private int count(Iterator iterator)
    {
        int i = 0;
        while (iterator.hasNext())
        {
            iterator.next();
            i++;
        }
        return i;
    }

}
