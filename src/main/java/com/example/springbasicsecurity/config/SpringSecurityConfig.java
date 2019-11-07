package com.example.springbasicsecurity.config;

import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password
                (passwordEncoder().encode("password")).roles("ADMIN");
        auth.inMemoryAuthentication().withUser("admin1").password
                (passwordEncoder().encode("password1")).roles("USER");
    }

    //security for all API
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //http.csrf().disable();
        http.authorizeRequests().anyRequest().authenticated().and().httpBasic();
    }

    //security based on URL
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //super.configure(http);
//        http.csrf().disable();
//        http.authorizeRequests().antMatchers("/rest/**").fullyAuthenticated().and().httpBasic();
//    }

    // security based on role
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //super.configure(http);
//        http.csrf().disable();
//        http.authorizeRequests().antMatchers("/rest/**").hasAnyRole("USER").anyRequest()
//                .fullyAuthenticated().and().httpBasic();
//    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
