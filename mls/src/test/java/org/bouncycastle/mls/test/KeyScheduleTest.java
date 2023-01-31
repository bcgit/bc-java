package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.*;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

import java.nio.charset.StandardCharsets;

public class KeyScheduleTest
    extends TestCase
{
    private final CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    public void testCreatorMemberJoiner() throws Exception {
        // Initialize the creator's key schedule (alice0)
        KeyScheduleEpoch alice0 = KeyScheduleEpoch.forCreator(suite);

        // Alice adds Bob via Welcome (alice1, bob1)
        // TODO add PSKs
        Secret commitSecret0 = new Secret("commit secret is 'commitsecret0'".getBytes(StandardCharsets.UTF_8));
        byte[] context0 = "context0".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize0 = TreeSize.forLeaves(2);

        KeyScheduleEpoch.JoinSecrets aliceJoin1 = alice0.startCommit(commitSecret0, null, context0);

        KeyScheduleEpoch.JoinSecrets bobJoin1 = new KeyScheduleEpoch.JoinSecrets(suite, aliceJoin1.joinerSecret, null);
        KeyScheduleEpoch bob1 = bobJoin1.complete(treeSize0, context0);

        KeyScheduleEpoch alice1 = aliceJoin1.complete(treeSize0, context0);
        assertEquals(alice1, bob1);

        // Bob adds Charlie via Welcome (alice2, bob2, charlie2)
        Secret commitSecret1 = new Secret("commit secret is 'commitsecret1'".getBytes(StandardCharsets.UTF_8));
        byte[] context1 = "context1".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize1 = TreeSize.forLeaves(3);

        KeyScheduleEpoch.JoinSecrets bobJoin2 = bob1.startCommit(commitSecret1, null, context1);

        KeyScheduleEpoch.JoinSecrets charlieJoin2 = new KeyScheduleEpoch.JoinSecrets(suite, bobJoin2.joinerSecret, null);
        KeyScheduleEpoch charlie2 = charlieJoin2.complete(treeSize1, context1);

        KeyScheduleEpoch bob2 = bobJoin2.complete(treeSize1, context1);
        KeyScheduleEpoch alice2 = alice1.next(treeSize1, null, commitSecret1, null, context1);

        assertEquals(alice2, bob2);
        assertEquals(bob2, charlie2);
        assertEquals(charlie2, alice2);
    }

    public void testExternalJoin() throws Exception {
        // Initialize the creator's key schedule (alice0)
        // Add another member via Welcome (alice1, bob1)
        // Add a member via external join (alice2, bob2, charlie2)
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
