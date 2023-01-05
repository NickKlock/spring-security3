package com.hextrix.springsecurity3;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity
    ) throws Exception {
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();
        delegate.setCsrfRequestAttributeName("_csrf");
        CsrfTokenRequestHandler requestHandler = delegate::handle;

        return httpSecurity
                .csrf(csrf -> csrf
                        .csrfTokenRepository(tokenRepository)
                        .csrfTokenRequestHandler(requestHandler))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .httpBasic()
                .and()
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,"/login").permitAll()
                        .requestMatchers("/any-endpoint").permitAll()
                        .requestMatchers("/admin-only").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .build();
    }
}
