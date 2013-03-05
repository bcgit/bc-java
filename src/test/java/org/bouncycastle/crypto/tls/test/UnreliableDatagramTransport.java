package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.util.Random;

import org.bouncycastle.crypto.tls.DatagramTransport;

public class UnreliableDatagramTransport implements DatagramTransport {

    private final DatagramTransport transport;
    private final Random random;
    private int percentPacketLoss;

    public UnreliableDatagramTransport(DatagramTransport transport, Random random,
        int percentPacketLoss) {
        if (percentPacketLoss < 0 || percentPacketLoss > 100)
            throw new IllegalArgumentException("'percentPacketLoss' out of range");

        this.transport = transport;
        this.random = random;
        this.percentPacketLoss = percentPacketLoss;
    }

    public int getReceiveLimit() throws IOException {
        return transport.getReceiveLimit();
    }

    public int getSendLimit() throws IOException {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        int length = transport.receive(buf, off, len, waitMillis);
        if (length >= 0) {
            if (lostPacket()) {
                // TODO Better to keep waiting if time left
                System.out.println("PACKET LOSS (" + length + " byte packet not received)");
                return -1;
            }
        }
        return length;
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        if (lostPacket()) {
            System.out.println("PACKET LOSS (" + len + " byte packet not sent)");
        } else {
            transport.send(buf, off, len);
        }
    }

    private boolean lostPacket() {
        return random.nextInt(100) < percentPacketLoss;
    }
}
