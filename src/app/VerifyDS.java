/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package app;
import java.io.*;
import java.security.*;
import java.security.spec.*;

/**
 *
 * @author Gigabyte
 */
public class VerifyDS {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            //Importar la clave publica
            FileInputStream keyfis = new FileInputStream("ds/publicKey.obj");
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            //Importar la firma en bytes
            FileInputStream sigfis = new FileInputStream("ds/signature.obj");
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            //Crear objeto Signature e inicializarlo con la clave publica
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
            sig.initVerify(pubKey);
            //Actualizar y verificar 
            FileInputStream datafis = new FileInputStream("ds/sample.obj");
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            };

            bufin.close();

            boolean ok = sig.verify(sigToVerify);

            System.out.println("firma verificada correctamente: " + ok);

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}
