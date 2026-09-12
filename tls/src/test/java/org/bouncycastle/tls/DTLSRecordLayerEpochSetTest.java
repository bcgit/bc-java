package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;

import junit.framework.TestCase;

/**
 * RFC 9147 4.2.2 and 8. The record layer resolves a received record's epoch from one ordered collection of
 * live read epochs, iterated most recent first, and writes at an epoch through the same collection.
 * <p>
 * The load-bearing test here is {@link #testAliasingEpochResolvesToTheMostRecentMatch()}: only the low 2
 * epoch bits are on the wire, so two live epochs can alias, and the RFC resolves that to the most recent of
 * them. That test fails if the iteration order in {@code getLiveReadEpochs} is reversed - which is the only
 * thing that makes it a test of the order rather than of the lookup.
 * </p>
 */
public class DTLSRecordLayerEpochSetTest
    extends TestCase
{
    /** Records the epoch a post-handshake handshake record was attributed to. */
    private static class RecordingRetransmit
        implements DTLSHandshakeRetransmit
    {
        int epoch = -1;
        int count = 0;

        public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
        {
            this.epoch = epoch;
            this.count++;
        }
    }

    private DTLSRecordLayer13TestSupport support;
    private RecordingRetransmit clientRetransmit;

    /**
     * A pair whose handshakes complete with a retransmit handler on each side, so that each side retains the
     * handshake epoch (RFC 9147 5.8.1) and the client additionally retains the plaintext epoch 0.
     */
    private void setUpPairWithRetainedEpochs() throws IOException
    {
        clientRetransmit = new RecordingRetransmit();

        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, clientRetransmit,
            new RecordingRetransmit());
    }

    private static int[] epochNumbers(DTLSRecordLayer recordLayer)
    {
        Vector liveReadEpochs = recordLayer.getLiveReadEpochs();
        int[] result = new int[liveReadEpochs.size()];
        for (int i = 0; i < result.length; ++i)
        {
            result[i] = ((DTLSEpoch)liveReadEpochs.elementAt(i)).getEpoch();
        }
        return result;
    }

    private static DTLSEpoch liveReadEpoch(DTLSRecordLayer recordLayer, int index)
    {
        return (DTLSEpoch)recordLayer.getLiveReadEpochs().elementAt(index);
    }

    /**
     * An epoch built with a cipher keyed exactly like the side's own, so that it can decode the same records
     * its real epochs can. That is what lets a test tell which of two aliasing epochs a record resolved to:
     * both can decode it, so only the resolution order decides which one does.
     */
    private static DTLSEpoch createAliasEpoch(DTLSRecordLayer13TestSupport.Side side, int epoch)
        throws IOException
    {
        DTLSEpoch readEpoch = liveReadEpoch(side.recordLayer, 0);

        return new DTLSEpoch(epoch, TlsUtils.initCipher(side.context), readEpoch.getRecordHeaderLengthRead(),
            readEpoch.getRecordHeaderLengthWrite());
    }

    /**
     * The collection is ordered most recent first: the current read epoch, then anything retained across a key
     * update, then the handshake epoch, then - on the client only - the plaintext epoch 0.
     */
    public void testLiveReadEpochsAreOrderedMostRecentFirst() throws Exception
    {
        setUpPairWithRetainedEpochs();

        int[] clientEpochs = epochNumbers(support.client.recordLayer);
        assertEquals(3, clientEpochs.length);
        assertEquals(3, clientEpochs[0]);
        assertEquals(2, clientEpochs[1]);
        assertEquals(0, clientEpochs[2]);

        // Epoch 0 is unauthenticated and only the client has a reason to read it, so the server does not hold it
        int[] serverEpochs = epochNumbers(support.server.recordLayer);
        assertEquals(2, serverEpochs.length);
        assertEquals(3, serverEpochs[0]);
        assertEquals(2, serverEpochs[1]);

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        support.client.recordLayer.retainReadEpoch(retained);

        int[] afterRetain = epochNumbers(support.client.recordLayer);
        assertEquals(4, afterRetain.length);
        assertEquals(3, afterRetain[0]);
        assertEquals("a retained pre-update read epoch ranks below the current read epoch and above the rest",
            6, afterRetain[1]);
        assertEquals(2, afterRetain[2]);
        assertEquals(0, afterRetain[3]);
    }

    /**
     * RFC 9147 4.2.2: "the most recent past epoch which has matching bits". Epochs 6 and 2 share the low 2
     * bits that are on the wire, and both are live and able to decode the record, so the only thing that
     * decides which one the record is attributed to is the order the collection is iterated in.
     * <p>
     * Mutation this test is built to catch: reverse the iteration in {@code getLiveReadEpochs} (or in its
     * consumer in {@code processDTLS13Record}) and the record resolves to epoch 2 instead, failing every
     * assertion below.
     * </p>
     */
    public void testAliasingEpochResolvesToTheMostRecentMatch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        // The client's retained handshake epoch, which epoch 6 will alias: 6 & 3 == 2 & 3
        DTLSEpoch handshakeEpoch = liveReadEpoch(clientLayer, 1);
        assertEquals(2, handshakeEpoch.getEpoch());

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        clientLayer.retainReadEpoch(retained);

        // A record the server sends at epoch 2 therefore reaches the client with epoch bits that match both
        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };
        support.server.recordLayer.sendHandshakeRecordAtEpoch(2, body, 0, body.length);

        DTLSRecordLayer13TestSupport.receive(support.client, 200);

        assertEquals("the record must be attributed to exactly one epoch", 1, clientRetransmit.count);
        assertEquals("an aliasing record resolves to the most recent matching epoch", 6, clientRetransmit.epoch);

        assertEquals("the most recent matching epoch consumed the record", 0,
            retained.getReplayWindow().getLatestConfirmedSeq());
        assertEquals("an older aliasing epoch must not have seen the record", -1,
            handshakeEpoch.getReplayWindow().getLatestConfirmedSeq());
    }

    /**
     * The read and the write sides resolve through the same collection, so an epoch that can be read can also
     * be written at. Before the refactor the two sides probed separate lists of fields and could disagree.
     */
    public void testRetainedReadEpochIsAlsoResolvedForWriting() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        clientLayer.retainReadEpoch(retained);

        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };
        DTLSRecordNumber recordNumber = clientLayer.sendHandshakeRecordAtEpoch(6, body, 0, body.length);

        assertNotNull(recordNumber);
        assertEquals(6, recordNumber.getEpoch());
        assertFalse(support.clientToServer.datagrams.isEmpty());
    }

    /**
     * RFC 9147 8 forbids sending at a new epoch until the peer's KeyUpdate has been acknowledged, so a second
     * key update cannot begin while the first update's epoch is still retained. The bound is asserted rather
     * than assumed: an unbounded set driven by peer-controlled key updates is a memory-growth denial of
     * service.
     */
    public void testAtMostOneRetainedReadEpoch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        clientLayer.retainReadEpoch(createAliasEpoch(support.client, 4));

        try
        {
            clientLayer.retainReadEpoch(createAliasEpoch(support.client, 5));
            fail("expected a second retained read epoch to be refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        int[] epochs = epochNumbers(clientLayer);
        assertEquals("the live read epoch set stays bounded", 4, epochs.length);
        assertEquals(4, epochs[1]);
    }

    public void testRetainReadEpochRejectsNull() throws Exception
    {
        setUpPairWithRetainedEpochs();

        try
        {
            support.client.recordLayer.retainReadEpoch(null);
            fail("expected a null retained read epoch to be refused");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}
