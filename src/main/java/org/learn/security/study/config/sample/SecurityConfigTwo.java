package org.learn.security.study.config;


import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// multi filter chains
//@Configuration
//@EnableWebSecurity
//@Order(0)
public class SecurityConfigTwo extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.antMatcher("/admin/**")
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.formLogin();
	}
}
