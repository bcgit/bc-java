package org.bouncycastle.tls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;

public class PSKTls13ClientTest
{
    public static void main(String[] args) throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        long time0 = System.currentTimeMillis();

        MockPSKTls13Client client = new MockPSKTls13Client();
        TlsClientProtocol protocol = openTlsConnection(address, port, client);

        long time1 = System.currentTimeMillis();
        System.out.println("Elapsed: " + (time1 - time0) + "ms");

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));
        output.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(">>> " + line);
        }

        protocol.close();
    }

    static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);
        return protocol;
    }
}
