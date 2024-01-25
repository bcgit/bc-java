package org.bouncycastle.mls.client;

import java.io.IOException;

import io.grpc.Server;
import io.grpc.ServerBuilder;

public class MLSServer
{
    public static void main(String[] args)
        throws IOException, InterruptedException
    {
        Server server1 = ServerBuilder.forPort(12346)
            .addService(new MLSClientImpl())
            .build();

        server1.start();
        server1.awaitTermination();
    }
}
