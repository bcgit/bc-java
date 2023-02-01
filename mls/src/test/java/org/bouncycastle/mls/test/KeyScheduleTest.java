package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.*;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.mls.protocol.ResumptionPSKUsage;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class KeyScheduleTest
    extends TestCase
{
    private final CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    private final KeyScheduleEpoch.PSKWithSecret externalPSK = new KeyScheduleEpoch.PSKWithSecret(
            PreSharedKeyID.external(
                    Hex.decode("00010203"),
                    Hex.decode("04050607")
            ),
            new Secret("an externally provisioned PSK".getBytes())
    );
    private final KeyScheduleEpoch.PSKWithSecret resumptionPSK = new KeyScheduleEpoch.PSKWithSecret(
            PreSharedKeyID.resumption(
                    ResumptionPSKUsage.APPLICATION,
                    Hex.decode("10111213"),
                    0xa0a0a0a0a0a0a0a0L,
                    Hex.decode("14151617")),
            new Secret("a resumption PSK".getBytes())
    );
    private final List<KeyScheduleEpoch.PSKWithSecret> psks = Arrays.asList(externalPSK, resumptionPSK);


    public void testCreatorMemberJoiner() throws Exception {
        // Initialize the creator's key schedule (alice0)
        KeyScheduleEpoch alice0 = KeyScheduleEpoch.forCreator(suite);

        // Alice adds Bob via Welcome (alice1, bob1)
        Secret commitSecret1 = new Secret("commit secret is 'commitsecret1'".getBytes(StandardCharsets.UTF_8));
        byte[] context1 = "context1".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize1 = TreeSize.forLeaves(2);

        KeyScheduleEpoch.JoinSecrets aliceJoin1 = alice0.startCommit(commitSecret1, psks, context1);

        KeyScheduleEpoch.JoinSecrets bobJoin1 = new KeyScheduleEpoch.JoinSecrets(suite, aliceJoin1.joinerSecret, psks);
        KeyScheduleEpoch bob1 = bobJoin1.complete(treeSize1, context1);

        KeyScheduleEpoch alice1 = aliceJoin1.complete(treeSize1, context1);
        assertEquals(alice1, bob1);

        // Bob adds Charlie via Welcome (alice2, bob2, charlie2)
        Secret commitSecret2 = new Secret("commit secret is 'commitsecret2'".getBytes(StandardCharsets.UTF_8));
        byte[] context2 = "context2".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize2 = TreeSize.forLeaves(3);

        KeyScheduleEpoch.JoinSecrets bobJoin2 = bob1.startCommit(commitSecret2, psks, context2);

        KeyScheduleEpoch.JoinSecrets charlieJoin2 = new KeyScheduleEpoch.JoinSecrets(suite, bobJoin2.joinerSecret, psks);
        KeyScheduleEpoch charlie2 = charlieJoin2.complete(treeSize2, context2);

        KeyScheduleEpoch bob2 = bobJoin2.complete(treeSize2, context2);
        KeyScheduleEpoch alice2 = alice1.next(treeSize2, null, commitSecret2, psks, context2);

        assertEquals(alice2, bob2);
        assertEquals(bob2, charlie2);
        assertEquals(charlie2, alice2);
    }

    public void testExternalJoin() throws Exception {
        // Initialize the creator's key schedule (alice0)
        KeyScheduleEpoch alice0 = KeyScheduleEpoch.forCreator(suite);

        // Bob joins via external Commit using GroupInfo posted by Alice (alice1, bob1)
        Secret commitSecret1 = new Secret("commit secret is 'commitsecret1'".getBytes(StandardCharsets.UTF_8));
        byte[] context1 = "context1".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize1 = TreeSize.forLeaves(2);

        KeyScheduleEpoch.ExternalInitParams bobJoin = new KeyScheduleEpoch.ExternalInitParams(suite, alice0.getExternalPublicKey());

        KeyScheduleEpoch bob1 = KeyScheduleEpoch.forExternalJoiner(suite, treeSize1, bobJoin, commitSecret1, psks, context1);
        KeyScheduleEpoch alice1 = alice0.next(treeSize1, bobJoin.getKEMOutput(), commitSecret1, psks, context1);

        assertEquals(alice1, bob1);

        // Charle joins via external Commit using GroupInfo posted by Bob (alice2, bob2, charlie2)
        Secret commitSecret2 = new Secret("commit secret is 'commitsecret2'".getBytes(StandardCharsets.UTF_8));
        byte[] context2 = "context2".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize2 = TreeSize.forLeaves(3);

        KeyScheduleEpoch.ExternalInitParams charlieJoin = new KeyScheduleEpoch.ExternalInitParams(suite, bob1.getExternalPublicKey());

        KeyScheduleEpoch charlie2 = KeyScheduleEpoch.forExternalJoiner(suite, treeSize2, charlieJoin, commitSecret2, psks, context2);
        KeyScheduleEpoch alice2 = alice1.next(treeSize2, charlieJoin.getKEMOutput(), commitSecret2, psks, context2);
        KeyScheduleEpoch bob2 = bob1.next(treeSize2, charlieJoin.getKEMOutput(), commitSecret2, psks, context2);

        assertEquals(alice2, bob2);
        assertEquals(bob2, charlie2);
        assertEquals(charlie2, alice2);
    }

    public static TestSuite suite()
    {
        return new TestSuite(KeyScheduleTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}
