package org.bouncycastle.mls.client;

import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;

public class MLSServer
{
    public static void main(String[] args) throws IOException, InterruptedException
    {
        Server server1 = ServerBuilder.forPort(12346)
                .addService(new MLSClientImpl())
                .build();

//        Server server2 = ServerBuilder.forPort(12347)
//                .addService(new MLSClientImpl())
//                .build();

        server1.start();
//        server2.start();

        server1.awaitTermination();
//        server2.awaitTermination();
    }
}
