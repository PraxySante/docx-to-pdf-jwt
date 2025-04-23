package dev.alhaddar.docxtopdf.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.RSAKeyProvider
import dev.alhaddar.docxtopdf.logger
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.io.ByteArrayInputStream

class VerifyJWT(
    private val secret: String = "",  // Rendu optionnel avec une valeur par défaut vide
    private val algorithm: String = "RS256",
    private val publicKey: String = "",
    private val provider: String = "https://auth.praxysante.fr/",
    private val enabled: Boolean = true,
) {
    val logger = logger()
    
    // Vérifie si l'authentification est possible avec les paramètres fournis
    private val isAuthConfigValid: Boolean by lazy {
        if (!enabled) return@lazy false
        
        when (algorithm) {
            "HS256" -> secret.isNotEmpty()
            "RS256" -> publicKey.isNotEmpty()
            else -> false
        }.also { isValid ->
            if (!isValid) {
                logger.warn("Configuration d'authentification invalide: algorithme=$algorithm, clés disponibles=${if (secret.isNotEmpty()) "secret" else ""}${if (publicKey.isNotEmpty()) ", publicKey" else ""}")
            }
        }
    }

    private val jwtAlgorithm: Algorithm? by lazy {
        if (!isAuthConfigValid) return@lazy null
        
        try {
            when (algorithm) {
                "HS256" -> Algorithm.HMAC256(secret)
                "RS256" -> {
                    val keyProvider = object : RSAKeyProvider {
                        override fun getPublicKeyById(keyId: String?): RSAPublicKey {
                            return parsePublicKey(publicKey)
                        }

                        override fun getPrivateKey(): RSAPrivateKey? {
                            return if (secret.isNotEmpty()) {
                                try {
                                    val keyFactory = KeyFactory.getInstance("RSA")
                                    val privateKeySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(secret))
                                    keyFactory.generatePrivate(privateKeySpec) as RSAPrivateKey
                                } catch (e: Exception) {
                                    logger.error("Erreur lors du traitement de la clé privée: ${e.message}")
                                    null
                                }
                            } else {
                                null
                            }
                        }

                        override fun getPrivateKeyId(): String {
                            return ""
                        }
                    }
                    
                    Algorithm.RSA256(keyProvider)
                }
                else -> {
                    logger.error("Algorithme non supporté: $algorithm")
                    null
                }
            }
        } catch (e: Exception) {
            logger.error("Erreur lors de l'initialisation de l'algorithme $algorithm: ${e.message}")
            null
        }
    }
    
    // Fonction pour analyser et convertir la chaîne de clé publique
    private fun parsePublicKey(pubKeyString: String): RSAPublicKey {
        val cleanKey = pubKeyString.replace("\n", "")
        
        return if (cleanKey.contains("BEGIN CERTIFICATE")) {
            logger.debug("Traitement d'un certificat PEM")
            val normalizedPEM = normalizePEM(cleanKey)
            val cf = CertificateFactory.getInstance("X.509")
            val inputStream = ByteArrayInputStream(normalizedPEM.toByteArray())
            val cert = cf.generateCertificate(inputStream)
            cert.publicKey as RSAPublicKey
        } else {
            logger.debug("Traitement d'une clé publique au format Base64")
            val keyFactory = KeyFactory.getInstance("RSA")
            val decodedKey = Base64.getDecoder().decode(cleanKey)
            val keySpec = X509EncodedKeySpec(decodedKey)
            keyFactory.generatePublic(keySpec) as RSAPublicKey
        }
    }
    
    // Fonction pour normaliser le format du certificat PEM
    private fun normalizePEM(pemString: String): String {
        logger.debug("Format du certificat original: ${pemString.replace("\n", "\\n")}")
        
        // Nettoyer le certificat PEM et formater correctement
        val cleanedPem = pemString
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
        
        // Reformater avec le format PEM standard (64 caractères par ligne)
        return "-----BEGIN CERTIFICATE-----\n" +
               cleanedPem.chunked(64).joinToString("\n") +
               "\n-----END CERTIFICATE-----"
    }
    
    private val verifier: JWTVerifier? by lazy {
        if (jwtAlgorithm == null) return@lazy null
        
        try {
            JWT.require(jwtAlgorithm).withIssuer(provider).build()
        } catch (e: Exception) {
            logger.error("Erreur lors de la création du vérificateur JWT: ${e.message}")
            null
        }
    }

    data class TokenVerificationResult(
        val valid: Boolean,
        val code: Int,
        val message: String
    )

    fun verifyToken(token: String): TokenVerificationResult {
        logger.info("_______________________________________________________________________________________________")
        logger.info("Vérification du token JWT, ${token.take(15)}...")
        
        if (!enabled || !isAuthConfigValid || verifier == null) {
            logger.warn("Authentification désactivée ou configuration invalide - token accepté par défaut")
            return TokenVerificationResult(true, 200, "Authentication disabled or invalid configuration")
        }
        
        // Utiliser l'opérateur de non-nullité pour dire au compilateur que verifier ne peut pas être null ici
        val safeVerifier = verifier!!
        return try {
            safeVerifier.verify(token)
            TokenVerificationResult(
                valid = true,
                code = 200,
                message = "Token is valid"
            )
        } catch (exception: JWTVerificationException) {
            if (exception.message == "The Token has expired") {
                logger.warn("JWT token expiré")
                TokenVerificationResult(
                    valid = false,
                    code = 401,
                    message = "Token expired"
                )
            } else {
                logger.warn("Token JWT invalide: ${exception.message}")
                TokenVerificationResult(
                    valid = false,
                    code = 403,
                    message = "Invalid token"
                )
            }
        }
    }
}