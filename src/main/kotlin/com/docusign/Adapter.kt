import com.docusign.esign.client.auth.OAuth
import com.docusign.DocusignAuthenticator
import com.docusign.esign.api.EnvelopesApi

class Adapter {

    private var authenticator: DocusignAuthenticator
    private var impersonatedUser: OAuth.UserInfo

    init {
        authenticator = DocusignAuthenticator()
        impersonatedUser = authenticator.apiClient.getUserInfo(authenticator.token.accessToken)
    }

    fun doAThing() {
        val client = authenticator.apiClient
        val envelopeApi = EnvelopesApi(client)

        println(envelopeApi.getEnvelope(impersonatedUser.accounts[0].accountId, "c0a58373-7a15-4d90-afd5-913a541d925c"))
    }
}