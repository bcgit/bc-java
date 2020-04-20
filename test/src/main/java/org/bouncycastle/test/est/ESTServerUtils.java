package org.bouncycastle.test.est;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Structure;

public class ESTServerUtils
{

    private static final Lock lock = new ReentrantLock();


    public static File makeRelativeToServerHome(String path)
        throws Exception
    {
        String ciscoHome = System.getenv("CISCO_EST_SERVER_HOME");
        if (ciscoHome == null)
        {
            File f = new File("cisco");
            if (f.exists())
            {
                ciscoHome = f.getCanonicalPath();
            }
            else
            {
                throw new RuntimeException("CISCO_EST_SERVER_HOME not defined.");
            }
        }

        return new File(ciscoHome, path).getCanonicalFile();
    }


    public static ServerInstance startServer(final EstServerConfig config)
    {
        final CLibrary server = (CLibrary)Native.loadLibrary("estserverwrap", CLibrary.class);
        final CountDownLatch exited = new CountDownLatch(1);
        Thread t = new Thread(new Runnable()
        {
            public void run()
            {
                try
                {
                    if (lock.tryLock(60, TimeUnit.SECONDS))
                    {
                        try
                        {

                            server.start_server(config);
                            exited.countDown();
                        }
                        finally
                        {
                            lock.unlock();
                        }
                    }
                    else
                    {
                        throw new IllegalStateException("Unable to obtain server lock.");
                    }
                }
                catch (Throwable t)
                {
                    throw new RuntimeException(t.getMessage(), t);
                }
            }
        });
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();

        waitForSocket(config.tcpPort);
        return new ServerInstance(server, config, exited);
    }


    public static void waitForSocket(int port)
    {
        long notAfter = System.currentTimeMillis() + 5000;
        for (; System.currentTimeMillis() < notAfter; )
        {

            Socket sock = null;
            try
            {
                Thread.sleep(100);
                sock = new Socket("127.0.0.1", port);
                break;
            }
            catch (Exception ex)
            {
                // Ignored.
            }
            finally
            {
                if (sock != null)
                {
                    try
                    {
                        sock.close();
                    }
                    catch (IOException e)
                    {
                        // Ignore this as well.
                    }
                }
            }
        }
    }

    /**
     * Holds the server and the configuration
     */
    public static class ServerInstance
    {
        private final CLibrary server;
        private final EstServerConfig estServerConfig;
        private final CountDownLatch exited;


        public ServerInstance(CLibrary server, EstServerConfig estServerConfig, CountDownLatch exited)
        {
            this.server = server;
            this.estServerConfig = estServerConfig;
            this.exited = exited;
        }

        public CLibrary getServer()
        {
            return server;
        }

        public EstServerConfig getEstServerConfig()
        {
            return estServerConfig;
        }


        public void stopServer()
            throws Exception
        {
            server.stop_server();
            exited.await(60, TimeUnit.SECONDS);
        }

    }


    public interface CLibrary
        extends Library
    {
        int start_server(EstServerConfig config);

        void stop_server();
    }

    public static class EstServerConfig
        extends Structure
    {
        public String srp;
        public boolean enforceCsr;
        public String httpAuthToken;
        public int manualEnroll;
        public boolean useDigestAuth;
        public boolean useBasicAuth;
        public boolean writeCSRToFile;
        public boolean disableHTTPAuth;
        public boolean disableHTTPWhenTLSSucceeds;
        public boolean verbose;
        public boolean enableCRLChecks;
        public boolean enableCheckPOPtoTLSUID;
        public boolean useIPV6;
        public int sleepDelay;
        public int tcpPort;
        public String serverCertPemFile;
        public String serverKeyPemFile;
        public String realm;
        public boolean fipsMode;
        public String estCSRAttr;
        public String estCACERTSResp;
        public String estTRUSTEDCerts;
        public String openSSLConfigFile;


        protected List<String> getFieldOrder()
        {
            return Arrays.asList("srp",
                "enforceCsr",
                "httpAuthToken",
                "manualEnroll",
                "useDigestAuth",
                "useBasicAuth",
                "writeCSRToFile",
                "disableHTTPAuth",
                "disableHTTPWhenTLSSucceeds",
                "verbose",
                "enableCRLChecks",
                "enableCheckPOPtoTLSUID",
                "useIPV6",
                "sleepDelay",
                "tcpPort",
                "serverCertPemFile",
                "serverKeyPemFile",
                "realm",
                "fipsMode",
                "estCSRAttr",
                "estCACERTSResp",
                "estTRUSTEDCerts",
                "openSSLConfigFile"
            );
        }
    }


}
