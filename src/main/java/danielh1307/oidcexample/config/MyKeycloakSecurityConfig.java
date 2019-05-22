package danielh1307.oidcexample.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@KeycloakConfiguration
public class MyKeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();

        // adding proper authority mapper for prefixing role with "ROLE_"
        // the given roles in realm_access (in JWT) are prefixed with "ROLE_"
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());

        // register KeycloakAuthenticationProvider with the authentication manager
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        // We can use new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl()), but in
        // this case we do not want to have a HttpSession and no session cookie so we
        // choose NullAuthenticatedSessionStrategy here
        return new NullAuthenticatedSessionStrategy();
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        // Use properties in application.properties instead of keycloak.json
        return new KeycloakSpringBootConfigResolver();
    }

    /**
     * Secure appropriate endpoints
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                // we do not want to set a session cookie
                .sessionManagement().sessionCreationPolicy(STATELESS).and()
                .authorizeRequests()
                .antMatchers("/secret/**").authenticated()
                .anyRequest().permitAll();
    }
}
