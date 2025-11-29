package com.example.adso.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;  
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Usamos CORS definido en CorsConfig.java
            .cors().and()
            
            // Deshabilitamos CSRF porque usamos JWT (stateless)
            .csrf(csrf -> csrf.disable())

            // Reglas de autorización
            .authorizeHttpRequests(authz -> authz
                    .requestMatchers("/auth/**").permitAll() // Login y registro
                    .requestMatchers(org.springframework.http.HttpMethod.POST, "/products").hasAuthority("ADMIN")
                    .requestMatchers(org.springframework.http.HttpMethod.GET, "/products").hasAnyAuthority("ADMIN", "USER")
                    .anyRequest().authenticated()
            )

            // Sesiones stateless
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Proveedor de autenticación
            .authenticationProvider(authenticationProvider)

            // Filtro JWT antes del filtro estándar
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
