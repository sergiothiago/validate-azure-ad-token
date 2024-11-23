package com.validate.ad.service;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;

@Service
public class AzureADValidateTokenService {

    private static final Logger logger = LoggerFactory.getLogger(AzureADValidateTokenService.class);
    private static final String JWKS_URL_TEMPLATE = "https://login.microsoftonline.com/%s/discovery/v2.0/keys";  // Template para a URL do JWKS

    @Value("${azure.ad.tenantid}")
    private String tenantId;

    public Boolean isTokenValid(String tokenJwt) {
        logger.info("Iniciando a validação do token JWT.");

        try {
            // URL do endpoint OpenID do Azure AD
            String jwksUrl = String.format(JWKS_URL_TEMPLATE, tenantId);

            // Configurando o processador de JWT
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwksUrl));

            jwtProcessor.setJWSKeySelector(new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(
                    com.nimbusds.jose.JWSAlgorithm.RS256, keySource
            ));
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>());

            // Processa e valida o token
            SignedJWT signedJWT = SignedJWT.parse(tokenJwt);
            var claims = jwtProcessor.process(signedJWT, null);

            // Logando as claims
            logger.info("Token válido! Claims: {}", claims.getClaims());

            return true;
        } catch (Exception e) {
            logError("Erro ao validar o token JWT", e);
            return false;
        } finally {
            logger.info("Finalizando a validação do token JWT.");
        }
    }

    private void logError(String message, Exception e) {
        logger.error(message);
        logger.error("Mensagem de erro: {}", e.getMessage());
        logger.error("Detalhes: {}", e.getLocalizedMessage());
        logger.error("StackTrace: ", e);  // Logando o stack trace de forma estruturada
    }
}
