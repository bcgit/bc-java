package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class UDPTransport implements DatagramTransport {

    private final DatagramSocket socket;
    private final int mtu;

    public UDPTransport(DatagramSocket socket, int mtu) throws IOException {
        if (!socket.isBound() || !socket.isConnected()) {
            throw new IllegalArgumentException("'socket' must be bound and connected");
        }
        this.socket = socket;
        
        // NOTE: As of JDK 1.6, can use NetworkInterface.getMTU
        this.mtu = mtu;
    }

    public int getReceiveLimit() {
        return mtu;
    }

    public int getSendLimit() {
        // TODO[DTLS] Maybe use a more conservative number, or implement Path-MTU discovery?
        return getReceiveLimit();
    }

    public void receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        socket.setSoTimeout(waitMillis);
        DatagramPacket packet = new DatagramPacket(buf, off, len);
        socket.receive(packet);
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        DatagramPacket packet = new DatagramPacket(buf, off, len);
        socket.send(packet);
    }
}
