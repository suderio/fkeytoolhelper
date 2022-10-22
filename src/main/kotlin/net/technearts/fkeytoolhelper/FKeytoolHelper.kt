package net.technearts.fkeytoolhelper

import picocli.CommandLine
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException

@CommandLine.Command(name = "keytool", mixinStandardHelpOptions = true)
class FKeytoolHelper : Runnable {
    @CommandLine.Parameters(paramLabel = "<filename>", description = ["The filename."])
    var fileName: String? = null

    @CommandLine.Parameters(paramLabel = "<alias>", description = ["The alias."])
    var alias: String? = null

    @CommandLine.Parameters(paramLabel = "<keystorePassword>", description = ["The keystore password."])
    var keystorePassword: String? = null

    @CommandLine.Parameters(paramLabel = "<entryPassword>", description = ["The entry password."])
    var entryPassword: String? = null
    override fun run() {
        System.out.printf("Using %s, file and %s entry.\n", fileName, alias)
        val storePass = keystorePassword!!.toCharArray()
        val entryPass = if (entryPassword!!.isNotEmpty()) {
            KeyStore.PasswordProtection(entryPassword!!.toCharArray())
        } else {
            null
        }
        val store = try {
            KeyStore.getInstance("JKS")
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        }
        val input = try {
            fileName?.let { FileInputStream(it) }
        } catch (e: FileNotFoundException) {
            System.out.printf("File %s, does not exist.\n", fileName)
            throw RuntimeException(e)
        }
        // Try loading the store
        try {
            store?.load(input, storePass)
        } catch (e: IOException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            System.out.printf("Algorithm does not exist.")
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            System.out.printf("Something wrong with the certificate.")
            throw RuntimeException(e)
        }
        // Try getting the entry
        val entry = (try {
            store?.getEntry(alias, entryPass)
        } catch (e: NoSuchAlgorithmException) {
            System.out.printf("Algorithm does not exist again.")
            throw RuntimeException(e)
        } catch (e: UnrecoverableEntryException) {
            System.out.printf("Things went completely south.")
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            System.out.printf("Something wrong with the keystore.")
            throw RuntimeException(e)
        }).also {
            println(it)
        }
    }
}