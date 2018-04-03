package foo;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Created by Lauren Girgis on 4/3/18.
 * Copyright © 2018 SAIC. All rights reserved.
 */

public class Foo {
  public static void main(String[] args) {
    try {
      //https://gist.github.com/milhomem/cd322bf3d0599ceb76fe
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      FileInputStream clientCertificateContent = new FileInputStream("src/main/java/foo/C02QL1WHG8WM-M.pfx");
      keyStore.load(clientCertificateContent, "password".toCharArray());

      KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(keyStore, "password".toCharArray());

      FileInputStream myTrustedCAFileContent = new FileInputStream("src/main/java/foo/ca_chain.cert.pem");
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      X509Certificate myCAPublicKey = (X509Certificate) certificateFactory.generateCertificate(myTrustedCAFileContent);

      KeyStore trustedStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustedStore.load(null);
      trustedStore.setCertificateEntry(myCAPublicKey.getSubjectX500Principal().getName(), myCAPublicKey);
      TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(trustedStore);
      TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, null);

      X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
      OkHttpClient client = new OkHttpClient();
      client.newBuilder().sslSocketFactory(sslContext.getSocketFactory(), trustManager); //BEFORE -> client.setSslSocketFactory(sslContext.getSocketFactory());

      Response response = client.newCall(new Request.Builder()
        .url("https://staging.bundler.refman.us/api/updates/RMIOS-791/00000002/DTG2017-08-23/BD2018-03-26T21:26:21.00Z.json")
        .build()
      ).execute();
      System.out.println(response);

    } catch (Exception e) {
      System.out.println("Error");
      System.out.println(e.getMessage());
    }
  }
}
