package com.csye7255.project.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;
    @Autowired
    private TokenStore tokenStore;

    @Value("${jwt.accessTokenValiditySeconds:120}")
    private int accessTokenValiditySeconds;

    @Value("${security.oauth2.client.client-id}")
    private String clientid;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    @Value("${security.oauth2.client.scope}")
    private String[] clientScope;

    @Override
    public void configure (ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory ()
                .withClient (clientid)
                .authorizedGrantTypes ("password", "authorization_code")
                .authorities ("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT", "USER")
                .scopes (clientScope)
                .autoApprove (true)
                .secret (passwordEncoder (). encode (clientSecret))
                .accessTokenValiditySeconds(accessTokenValiditySeconds);
    }
    // @Bean
    public PasswordEncoder passwordEncoder () {
        return new BCryptPasswordEncoder();
    }
    @Override
    public void configure (AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .pathMapping("/oauth/token", "/token")
                .authenticationManager (authenticationManager)
                .tokenStore (tokenStore);
    }
    @Bean
    public TokenStore tokenStore () {
        return new InMemoryTokenStore();
    }
}
