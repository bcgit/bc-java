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
        Secret commitSecret0 = new Secret("commit secret is 'commitsecret0'".getBytes(StandardCharsets.UTF_8));
        byte[] context0 = "context0".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize0 = TreeSize.forLeaves(2);

        KeyScheduleEpoch.JoinSecrets aliceJoin1 = alice0.startCommit(commitSecret0, psks, context0);

        KeyScheduleEpoch.JoinSecrets bobJoin1 = new KeyScheduleEpoch.JoinSecrets(suite, aliceJoin1.joinerSecret, psks);
        KeyScheduleEpoch bob1 = bobJoin1.complete(treeSize0, context0);

        KeyScheduleEpoch alice1 = aliceJoin1.complete(treeSize0, context0);
        assertEquals(alice1, bob1);

        // Bob adds Charlie via Welcome (alice2, bob2, charlie2)
        Secret commitSecret1 = new Secret("commit secret is 'commitsecret1'".getBytes(StandardCharsets.UTF_8));
        byte[] context1 = "context1".getBytes(StandardCharsets.UTF_8);
        TreeSize treeSize1 = TreeSize.forLeaves(3);

        KeyScheduleEpoch.JoinSecrets bobJoin2 = bob1.startCommit(commitSecret1, psks, context1);

        KeyScheduleEpoch.JoinSecrets charlieJoin2 = new KeyScheduleEpoch.JoinSecrets(suite, bobJoin2.joinerSecret, psks);
        KeyScheduleEpoch charlie2 = charlieJoin2.complete(treeSize1, context1);

        KeyScheduleEpoch bob2 = bobJoin2.complete(treeSize1, context1);
        KeyScheduleEpoch alice2 = alice1.next(treeSize1, null, commitSecret1, psks, context1);

        assertEquals(alice2, bob2);
        assertEquals(bob2, charlie2);
        assertEquals(charlie2, alice2);
    }

    public void testExternalJoin() throws Exception {
        // Initialize the creator's key schedule (alice0)
        // Another member joins via external commmit (alice1, bob1)
        // Another member joins via external commmit (alice2, bob2, charlie2)
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
