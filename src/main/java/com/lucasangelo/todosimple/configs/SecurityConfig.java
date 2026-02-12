package com.lucasangelo.todosimple.configs;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.lucasangelo.todosimple.security.JWTAuthenticationFilter;
import com.lucasangelo.todosimple.security.JWTAuthorizationFilter;
import com.lucasangelo.todosimple.security.JWTUtil;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

        @Autowired
        private JWTUtil jwtUtil;

        // Injetamos a configuração de autenticação do Spring Boot
        @Autowired
        private AuthenticationConfiguration authenticationConfiguration;

        @Autowired
        private UserDetailsService userDetailsService;

        private static final String[] PUBLIC_MATCHERS = {
                        "/"
        };

        private static final String[] PUBLIC_MATCHERS_POST = {
                        "/user",
                        "/login"
        };

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

                http.cors().and().csrf().disable();

                // Recuperamos o AuthenticationManager da configuração padrão do Spring
                AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

                http.authorizeRequests(requests -> requests
                                .antMatchers(HttpMethod.POST, PUBLIC_MATCHERS_POST).permitAll()
                                .antMatchers(PUBLIC_MATCHERS).permitAll()
                                .anyRequest().authenticated());

                // Passamos o authenticationManager recuperado para o filtro
                http.addFilter(new JWTAuthenticationFilter(authenticationManager, this.jwtUtil));
                http.addFilter(new JWTAuthorizationFilter(authenticationManager, this.jwtUtil,
                                this.userDetailsService));

                http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

                return http.build();
        }

        @Bean
        CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration().applyPermitDefaultValues();
                configuration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE"));
                final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                return new BCryptPasswordEncoder();
        }

}