package com.example.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/public/*").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .httpBasic()
//                .authenticationEntryPoint(entryPoint);
//    }

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http
           .csrf().disable()
           .authorizeHttpRequests().requestMatchers("/public/*").permitAll()
           .anyRequest().authenticated()
           .and()
//           .httpBasic()
           .formLogin();

      return http.build();
    }
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//    	auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
//        auth.inMemoryAuthentication()
//                .withUser("user").password("password")
//                .authorities("ROLE_USER")
//                .and()
//                .withUser("admin").password("password")
//                .authorities("ROLE_ADMIN")
//                .and()
//                .passwordEncoder(new BCryptPasswordEncoder());
        
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();

        UserDetails userOne = User.withUsername("admin").password("admin").authorities("ROLE_ADMIN").build();
        UserDetails userTwo = User.withUsername("user").password("user").authorities("ROLE_USER").build();

        userDetailsService.createUser(userOne);
        userDetailsService.createUser(userTwo);
        auth.userDetailsService(userDetailsService);
    }

//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
    @Bean
    public PasswordEncoder passwordEncoder() {
    	return NoOpPasswordEncoder.getInstance();
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
