package com.csye7255.project.service;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@EnableResourceServer
@RestController
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter{

    @RequestMapping("/pvt")
    public String pvt () {
        return "Private Page";
    }

    @RequestMapping("/public")
    public String pub() {
        return "Public Page";
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().antMatchers("/oauth/token", "/oauth/authorize**").permitAll()
                .anyRequest().authenticated();
//        http.requestMatchers().antMatchers("/pvt")
//                .and().authorizeRequests();
//                .antMatchers("/pvt").access("hasRole('USER')");
//                .and().requestMatchers().antMatchers("/admin")
//                .and().authorizeRequests()
//                .antMatchers("/admin").access("hasRole('ADMIN')");
    }

}
