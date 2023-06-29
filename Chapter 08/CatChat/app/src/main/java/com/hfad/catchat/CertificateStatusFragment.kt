@file: JvmName("CertificateStatusFragment")

// package com.tmhls.certmgmt.android
package com.hfad.catchat    

//import android.net.Uri
//import java.math.BigInteger

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import android.widget.Toast
import android.widget.Button
import android.os.CountDownTimer
import androidx.preference.PreferenceManager
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup

// import com.tmhls.certmgmt.android.databinding.ActivityCreateCertificateBinding
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
//import org.slf4j.LoggerFactory
import java.io.StringWriter
import java.security.*
import java.security.cert.Certificate
import java.util.*
import javax.security.auth.x500.X500Principal


class CertificateStatusFragment : Fragment() {

    companion object {
        private val TAG = CertificateStatusFragment::class.java.simpleName
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "CMS_KEY"
        private const val REQUEST_CODE_FOR_CREDENTIALS = 1
    }

    // preferences
    private lateinit var X500Principal_subject: String

    private lateinit var keyguardManager: KeyguardManager
    // private lateinit var keyPair: KeyPair
    private lateinit var signatureResult: String
    // private lateinit var binding: ActivityCreateCertificateBinding

    // private val log = LoggerFactory.getLogger(this.javaClass)

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_certificate_status, container, false)
        val createButton = view.findViewById<Button>(R.id.create_button)
				val context = activity!!

        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context /* Activity context */)
        val X500Principal_C = sharedPreferences.getString("country", "")
        val X500Principal_ST = sharedPreferences.getString("state", "")
        val X500Principal_L = sharedPreferences.getString("location", "")
        val X500Principal_O = sharedPreferences.getString("organization", "")
        val X500Principal_OU = sharedPreferences.getString("organization_unit", "")
        val mac_address = sharedPreferences.getString("mac_address", "")        
        val device_type = sharedPreferences.getString("device_type", "")
        val X500Principal_CN = "VanderlandeCA-${device_type}-${mac_address}.wal-mart.com"

        X500Principal_subject = "CN=${X500Principal_CN},OU=${X500Principal_OU},O=${X500Principal_O},L=${X500Principal_L},ST=${X500Principal_ST},C=${X500Principal_C}"

        //Check if lock screen has been set up. Just displaying a Toast here but it shouldn't allow the user to go forward.
        if (!keyguardManager.isDeviceSecure) {
            Toast.makeText(context, "Secure lock screen hasn't set up.", Toast.LENGTH_LONG).show()
        }

        //Check if the keys already exists to avoid creating them again
        if (!checkKeyExists()) {
            generateKey()
        }

        createButton.setOnClickListener {
            if (checkKeyExists()) {
                deleteKey()
            }
            generateKey()
        }
        
        return view
    }

    private fun generateKey() {
				val context = activity!!
        val startDate = GregorianCalendar()
        val endDate = GregorianCalendar()
        endDate.add(Calendar.DAY_OF_MONTH, 180) // maximum time allowed for Walmart

        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context /* Activity context */)
        val userAuthenticationRequired = sharedPreferences.getBoolean("user_authentication_required", false)
        val rsaKeySize = sharedPreferences.getString("rsa_key_size", "2048")!!.toInt()

        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
            Companion.ANDROID_KEYSTORE
        )
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
            //setCertificateSerialNumber(BigInteger.valueOf(777))                                           //Serial number used for the self-signed certificate of the generated key pair, default is 1
            setCertificateSubject(X500Principal(X500Principal_subject))                                     //Subject used for the self-signed certificate of the generated key pair, default is CN=fake
            setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512) //Set of digests algorithms with which the key can be used
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)                               //Set of padding schemes with which the key can be used when signing/verifying
            setCertificateNotBefore(startDate.time)                                                         //Start of the validity period for the self-signed certificate of the generated, default Jan 1 1970
            setCertificateNotAfter(endDate.time)                                                            //End of the validity period for the self-signed certificate of the generated key, default Jan 1 2048
            setUserAuthenticationRequired(userAuthenticationRequired)                                                             //Sets whether this key is authorized to be used only if the user has been authenticated, default false
            if (Build.VERSION.SDK_INT >= 23 && Build.VERSION.SDK_INT < 30) {
                setUserAuthenticationValidityDurationSeconds(30) //Duration(seconds) for which this key is authorized to be used after the user is successfully authenticated
            } else if (Build.VERSION.SDK_INT >= 30){
                setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            }
            if (Build.VERSION.SDK_INT >= 30) {
                if (userAuthenticationRequired) {
                    setUnlockedDeviceRequired(true)
                }
            }
            setKeySize(rsaKeySize)
            build()
        }

        //Initialization of key generator with the parameters we have specified above
        keyPairGenerator.initialize(parameterSpec)

        //Generates the key pair
        keyPairGenerator.generateKeyPair()
    }

    private fun checkKeyExists(): Boolean {
        //We get the Keystore instance
        val keyStore: KeyStore = KeyStore.getInstance(Companion.ANDROID_KEYSTORE).apply {
            load(null)
        }

        //We get the private and public key from the keystore if they exists
        val privateKey: PrivateKey? = keyStore.getKey(KEY_ALIAS, null) as PrivateKey?
        val publicKey: PublicKey? = keyStore.getCertificate(KEY_ALIAS)?.publicKey

        val result: Boolean = (privateKey != null && publicKey != null)

        return result
    }
     
    private fun deleteKey() {
        //We get the Keystore instance
        val keyStore: KeyStore = KeyStore.getInstance(Companion.ANDROID_KEYSTORE).apply {
            load(null)
        }

        //We get the private and public key from the keystore if they exists
        keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun sendData() {
        //We get the Keystore instance
        val keyStore: KeyStore = KeyStore.getInstance(Companion.ANDROID_KEYSTORE).apply {
            load(null)
        }

        //We get the certificate from the keystore
        val certificate: Certificate? = keyStore.getCertificate(KEY_ALIAS)

        if (certificate != null) {
            val intent = Intent(Intent.ACTION_SEND)
            // val base64PubKey = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
            // val csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64PubKey.replace("(.{1,64})".toRegex(), "$1\n") + "-----END CERTIFICATE REQUEST-----\n"
            val csr: String = getCSR()

            intent.type = "text/plain"
            intent.putExtra(Intent.EXTRA_SUBJECT, "CSR $KEY_ALIAS")
            intent.putExtra(Intent.EXTRA_TEXT, csr)
            startActivity(intent)
        }
    }

    private fun getCSR(): String {
        val keyStore: KeyStore = KeyStore.getInstance(Companion.ANDROID_KEYSTORE).apply {
            load(null)
        }
        val entry = keyStore.getEntry(KEY_ALIAS, null)
        //val certificate: Certificate? = keyStore.getCertificate(KEY_ALIAS)
        val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        for (i in 1..2) {
            try {
                val p10Builder: PKCS10CertificationRequestBuilder = JcaPKCS10CertificationRequestBuilder(
                    X500Principal(X500Principal_subject), publicKey
                )
                val csBuilder = JcaContentSignerBuilder("SHA256WithRSAEncryption")
                val signer: ContentSigner = csBuilder.build(privateKey)
                val csr: PKCS10CertificationRequest = p10Builder.build(signer)
                val csrAsString: StringWriter = StringWriter()
                val pemObject = PemObject("CERTIFICATE REQUEST", csr.encoded)
                val pemWriter = JcaPEMWriter(csrAsString)
                pemWriter.writeObject(pemObject)
                pemWriter.close()
                csrAsString.close()

                return csrAsString.toString()
            } catch (e: Exception) {
                if (i == 1) {
                    showAuthenticationScreen()
                } else {
                    throw e
                }
            }
        }
        return ""
    }

    // Obsolete below?

    private fun showAuthenticationScreen() {
        //This will open a screen to enter the user credentials (fingerprint, pin, pattern). We can display a custom title and description
        val intent: Intent? = keyguardManager.createConfirmDeviceCredentialIntent("Keystore Sign And Verify",
            "To be able to sign the data we need to confirm your identity. Please enter your pin/pattern or scan your fingerprint")
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_FOR_CREDENTIALS)
        }
    }
}
