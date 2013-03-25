package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Vector;

public class DTLSServerProtocol extends DTLSProtocol {

    protected boolean verifyRequests = true;

    public DTLSServerProtocol(SecureRandom secureRandom) {
        super(secureRandom);
    }

    public boolean getVerifyRequests() {
        return verifyRequests;
    }

    public void setVerifyRequests(boolean verifyRequests) {
        this.verifyRequests = verifyRequests;
    }

    public DTLSTransport connect(TlsServer server, DatagramTransport transport) throws IOException {

        if (server == null)
            throw new IllegalArgumentException("'server' cannot be null");
        if (transport == null)
            throw new IllegalArgumentException("'transport' cannot be null");

        ServerHandshakeState state = new ServerHandshakeState();
        state.server = server;
        state.serverContext = new TlsServerContextImpl(secureRandom, new SecurityParameters());
        state.serverContext.getSecurityParameters().serverRandom = TlsProtocol
            .createRandomBlock(secureRandom);
        server.init(state.serverContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.serverContext,
            ContentType.handshake);

        // TODO Need to handle sending of HelloVerifyRequest without entering a full connection

        DTLSReliableHandshake handshake = new DTLSReliableHandshake(recordLayer);

        DTLSReliableHandshake.Message clientMessage = handshake.receiveMessage();

        {
            // NOTE: After receiving a record from the client, we discover the record layer version
            ProtocolVersion client_version = recordLayer.getDiscoveredPeerVersion();
            // TODO Read RFCs for guidance on the expected record layer version number
            state.serverContext.setClientVersion(client_version);
        }

        if (clientMessage.getType() == HandshakeType.client_hello) {
            processClientHello(state, clientMessage.getBody());
            clientMessage = handshake.receiveMessage();
        } else {
            // TODO Alert
        }

        // TODO Send ServerHello

        Vector serverSupplementalData = state.server.getServerSupplementalData();
        if (serverSupplementalData != null) {
            byte[] supplementalDataBody = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        return null;
    }

    protected void processClientHello(ServerHandshakeState state, byte[] body) throws IOException {
        // TODO
    }

    protected static class ServerHandshakeState {
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        // int[] offeredCipherSuites = null;
        // short[] offeredCompressionMethods = null;
        // Hashtable clientExtensions = null;
        // boolean secure_renegotiation = false;
        // TlsKeyExchange keyExchange = null;
        // TlsAuthentication authentication = null;
        // CertificateRequest certificateRequest = null;
        // TlsCredentials clientCredentials = null;
    }
}
