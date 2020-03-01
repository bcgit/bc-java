package org.bouncycastle.jsse.provider;

import java.net.Socket;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

class TransportData
{
    static TransportData from(Socket socket)
    {
        if (!(socket instanceof SSLSocket && socket.isConnected()))
        {
            return null;
        }

        SSLSocket sslSocket = (SSLSocket)socket;

        BCSSLParameters parameters = SSLSocketUtil.importSSLParameters(sslSocket);
        if (null == parameters)
        {
            /*
             * NOTE: This will only be null before JDK 1.6 (meaning neither parameters nor handshake
             * session exist). For backward compatibility, our KeyManager/TrustManager
             * implementations will behave as if no transport was provided.
             */
            return null;
        }

        BCExtendedSSLSession handshakeSession = SSLSocketUtil.importHandshakeSession(sslSocket);

        return new TransportData(parameters, handshakeSession);
    }

    static TransportData from(SSLEngine engine)
    {
        if (null == engine)
        {
            return null;
        }

        BCSSLParameters parameters = SSLEngineUtil.importSSLParameters(engine);
        if (null == parameters)
        {
            /*
             * NOTE: This will only be null before JDK 1.6 (meaning neither parameters nor handshake
             * session exist). For backward compatibility, our KeyManager/TrustManager
             * implementations will behave as if no transport was provided.
             */
            return null;
        }

        BCExtendedSSLSession handshakeSession = SSLEngineUtil.importHandshakeSession(engine);

        return new TransportData(parameters, handshakeSession);
    }

    static BCAlgorithmConstraints getAlgorithmConstraints(TransportData transportData, boolean enableX509Constraints)
    {
        return null == transportData
            ?   new ProvAlgorithmConstraints(null, enableX509Constraints)
            :   transportData.getAlgorithmConstraints(enableX509Constraints);
    }

    private final BCSSLParameters parameters;
    private final BCExtendedSSLSession handshakeSession;

    private TransportData(BCSSLParameters parameters, BCExtendedSSLSession handshakeSession)
    {
        this.parameters = parameters;
        this.handshakeSession = handshakeSession;
    }

    BCSSLParameters getParameters()
    {
        return parameters;
    }

    BCExtendedSSLSession getHandshakeSession()
    {
        return handshakeSession;
    }

    BCAlgorithmConstraints getAlgorithmConstraints(boolean enableX509Constraints)
    {
        BCAlgorithmConstraints configAlgorithmConstraints = parameters.getAlgorithmConstraints();

        if (null == handshakeSession || !JsseUtils.isTLSv12(handshakeSession.getProtocol()))
        {
            return new ProvAlgorithmConstraints(configAlgorithmConstraints, enableX509Constraints);
        }

        String[] peerSigAlgsCert = handshakeSession.getPeerSupportedSignatureAlgorithms();

        return new ProvAlgorithmConstraints(configAlgorithmConstraints, peerSigAlgsCert, enableX509Constraints);
    }
}
