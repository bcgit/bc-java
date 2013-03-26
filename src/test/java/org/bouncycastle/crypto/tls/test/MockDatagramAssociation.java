package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.util.Vector;

import org.bouncycastle.crypto.tls.DatagramTransport;

public class MockDatagramAssociation {

    private int mtu;
    private MockDatagramTransport client, server;

    public MockDatagramAssociation(int mtu) {

        this.mtu = mtu;

        Vector clientQueue = new Vector();
        Vector serverQueue = new Vector();

        this.client = new MockDatagramTransport(clientQueue, serverQueue);
        this.server = new MockDatagramTransport(serverQueue, clientQueue);
    }

    public DatagramTransport getClient() {
        return client;
    }

    public DatagramTransport getServer() {
        return server;
    }

    private class MockDatagramTransport implements DatagramTransport {

        private Vector receiveQueue, sendQueue;

        MockDatagramTransport(Vector receiveQueue, Vector sendQueue) {
            this.receiveQueue = receiveQueue;
            this.sendQueue = sendQueue;
        }

        public int getReceiveLimit() throws IOException {
            return mtu;
        }

        public int getSendLimit() throws IOException {
            return mtu;
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
            synchronized (receiveQueue) {
                if (receiveQueue.isEmpty()) {
                    try {
                        receiveQueue.wait(waitMillis);
                    } catch (InterruptedException e) {
                        // TODO Keep waiting until full wait expired?
                    }
                    if (receiveQueue.isEmpty()) {
                        return -1;
                    }
                }
                DatagramPacket packet = (DatagramPacket) receiveQueue.remove(0);
                int copyLength = Math.min(len, packet.getLength());
                System.arraycopy(packet.getData(), packet.getOffset(), buf, off, copyLength);
                return copyLength;
            }
        }

        public void send(byte[] buf, int off, int len) throws IOException {
            if (len > mtu) {
                // TODO Simulate rejection?
            }

            DatagramPacket packet = new DatagramPacket(buf, off, len);
            synchronized (sendQueue) {
                sendQueue.addElement(packet);
                sendQueue.notify();
            }
        }
    }
}
