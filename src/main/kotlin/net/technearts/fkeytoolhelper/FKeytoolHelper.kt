package net.technearts.fkeytoolhelper

import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.security.*
import java.security.KeyStore.PrivateKeyEntry
import java.security.cert.CertificateException


@Command(name = "fkeytoolhelper", mixinStandardHelpOptions = true)
class FKeytoolHelper : Runnable {
    @Parameters(paramLabel = "<filename>", description = ["The filename."])
    private var fileName: String? = null

    @Parameters(paramLabel = "<alias>", description = ["The alias."])
    private var alias: String? = null

    @Parameters(paramLabel = "<keystorePassword>", description = ["The keystore password."])
    private var keystorePassword: String? = null

    @Parameters(paramLabel = "<entryPassword>", description = ["The entry password."])
    private var entryPassword: String? = null
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
        (try {
            store?.getEntry(alias, entryPass)
        } catch (e: NoSuchAlgorithmException) {
            System.out.printf("Algorithm does not exist again.")
            throw RuntimeException(e)
        } catch (e: UnrecoverableEntryException) {
            System.out.printf("This %s entry does not exist.", alias)
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            System.out.printf("Something wrong with the keystore.")
            throw RuntimeException(e)
        }).also {
            if (it is PrivateKeyEntry) {
                val myPrivateKey = it.privateKey
                println(myPrivateKey.encoded)
                println("-------------------")
                println(myPrivateKey.format)
                println("-------------------")
                println(myPrivateKey.algorithm)
                println("-------------------")
            } else {
                println("Not a private key")
                println(it)
            }
        }
    }
}