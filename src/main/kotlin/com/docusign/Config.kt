package com.docusign

object Config {

    const val EXPIRY_IN_SECONDS : Long = 3600
    val BASE_URL: String = System.getenv("baseUrl") ?: "default_value"
    val O_AUTH_BASE_URL: String = System.getenv("oAuthBaseUrl") ?: "default_value"
    val O_AUTH_ENDPOINT: String = System.getenv("oAuthEndpoint") ?: "default_value"
    val INTEGRATOR_KEY: String = System.getenv("integratorKey") ?: "default_value"
    val IMPERSONATED_USER: String = System.getenv("impersonatedUser") ?: "default_value"
    val PUBLIC_INTEGRATOR_RSA_KEY: String = System.getenv("publicIntegratorRSAKey") ?: "default_value"
    val PRIVATE_INTEGRATOR_RSA_KEY: String = System.getenv("privateIntegratorRSAKey") ?: "default_value"

}
