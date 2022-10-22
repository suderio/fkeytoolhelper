package net.technearts;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

@Command(name = "keytool", mixinStandardHelpOptions = true)
public class FKeytoolHelper implements Runnable {

    @Parameters(paramLabel = "<filename>", description = "The filename.")
    String fileName;
    @Parameters(paramLabel = "<alias>", description = "The alias.")
    String alias;
    @Parameters(paramLabel = "<keystorePassword>", description = "The keystore password.")
    String keystorePassword;
    @Parameters(paramLabel = "<entryPassword>", description = "The entry password.")
    String entryPassword;
    @Override
    public void run() {

        System.out.printf("Using %s, file and %s entry.\n", fileName, alias);

        char[] storePass = keystorePassword.toCharArray();
        KeyStore.ProtectionParameter entryPass;
        if (entryPassword.length() > 0) {
            entryPass = new KeyStore.PasswordProtection(entryPassword.toCharArray());
        } else {
            entryPass = null;
        }

        KeyStore store = null;
        try {
            store = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        InputStream input = null;
        try {
            input = new FileInputStream(fileName);
        } catch (FileNotFoundException e) {
            System.out.printf("File %s, does not exist.\n", fileName);
            throw new RuntimeException(e);
        }
        try {
            store.load(input, storePass);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("Algorithm does not exist.");
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            System.out.printf("Something wrong with the certificate.");
            throw new RuntimeException(e);
        }

        KeyStore.Entry entry = null;
        try {
            entry = store.getEntry(alias, entryPass);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableEntryException e) {
            System.out.printf("Things went completely south.");
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            System.out.printf("Something wrong with the keystore.");
            throw new RuntimeException(e);
        }
        System.out.println(entry);
    }
}
