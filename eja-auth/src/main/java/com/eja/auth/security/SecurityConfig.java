package com.eja.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // desactivar CSRF si usas JWT
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
        // Si tienes filtro JWT, agrégalo aquí, antes de UsernamePasswordAuthenticationFilter
        //.addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }

    // Si usas un filtro JWT personalizado, defínelo como @Bean y añádelo aquí
}
