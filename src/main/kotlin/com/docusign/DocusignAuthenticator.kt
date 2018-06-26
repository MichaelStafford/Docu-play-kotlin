package com.docusign

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.docusign.esign.client.ApiClient
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.ResponseDeserializable
import com.github.kittinunf.result.Result
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.security.KeyFactory
import java.security.NoSuchProviderException
import java.security.Security
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

data class Token(
        @SerializedName("access_token") val accessToken: String,
        @SerializedName("token_type")   val tokenType: String,
        @SerializedName("expires_in")   val expiresIn: Long
) {

    class Deserializer : ResponseDeserializable<Token> {
        override fun deserialize(content: String): Token? {
            return Gson().fromJson(content, Token::class.java)!!
        }
    }
}

class DocusignAuthenticator {

    val token: Token
    val apiClient: ApiClient

    init {
        token = authenticate()
        apiClient = setupClient()
    }

    private fun setupClient(): ApiClient {
        val apiClient = ApiClient(Config.BASE_URL)
        apiClient.setAccessToken(token.accessToken, System.currentTimeMillis() + token.expiresIn + Config.EXPIRY_IN_SECONDS)

        return apiClient
    }

    private fun authenticate(): Token {
        val token = generateToken()
        val params = listOf("grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" to token)

        val (_, _, result ) = Fuel.post("https://${Config.O_AUTH_BASE_URL}${Config.O_AUTH_ENDPOINT}", params)
                .header("Content-Type" to " application/x-www-form-urlencoded")
                .responseObject(Token.Deserializer())

        when(result) {
            is Result.Failure -> {
                throw result.getException()
            }
            is Result.Success -> {
                return result.get()
            }
        }
    }

    private fun generateToken(): String {
        val issueTime = System.currentTimeMillis()
        val algorithmRSA = Algorithm.RSA256(toPublicKey(Config.PUBLIC_INTEGRATOR_RSA_KEY), toPrivateKey(Config.PRIVATE_INTEGRATOR_RSA_KEY))
        val scope = "signature impersonation"

        return JWT.create()
                .withIssuer(Config.INTEGRATOR_KEY)
                .withSubject(Config.IMPERSONATED_USER)
                .withAudience(Config.O_AUTH_BASE_URL)
                .withIssuedAt(Date(issueTime))
                .withExpiresAt(Date(issueTime + Config.EXPIRY_IN_SECONDS))
                .withClaim("scope", scope)
                .sign(algorithmRSA)!!
    }

    fun toPrivateKey(key: String): RSAPrivateKey? {
        val stringReader = StringReader(key)
        val pemReader = PemReader(stringReader)

        pemReader.use { reader ->
            val pemObject = reader.readPemObject()
            val bytes = pemObject.content

            try {
                Security.addProvider(BouncyCastleProvider())
                val kf = KeyFactory.getInstance("RSA", "BC")
                val keySpec = PKCS8EncodedKeySpec(bytes)

                return kf.generatePrivate(keySpec)!! as RSAPrivateKey
            } catch (e: InvalidKeySpecException) {
                println("Could not reconstruct the private key")
            } catch (e: NoSuchProviderException) {
                println("Could not reconstruct the private key, invalid provider.")
            }
        }

        return null
    }

    fun toPublicKey(key: String): RSAPublicKey? {
        val stringReader = StringReader(key)
        val pemReader = PemReader(stringReader)

        pemReader.use { reader ->
            val pemObject = reader.readPemObject()
            val bytes = pemObject.content

            try {
                val kf = KeyFactory.getInstance("RSA")
                val keySpec = X509EncodedKeySpec(bytes)

                return kf.generatePublic(keySpec)!! as RSAPublicKey
            } catch (e: InvalidKeySpecException) {
                println("Could not reconstruct the public key")
            }
        }

        return null
    }
}