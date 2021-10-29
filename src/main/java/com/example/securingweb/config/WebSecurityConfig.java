package com.example.securingweb.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/use").hasRole("USER")
				.antMatchers("/admin**").hasRole("ADMIN")
				.antMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
				.and().httpBasic()
				.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.and()
			.logout()
				.permitAll()
				.and().csrf().disable();
	}
/*
	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		UserDetails user =
			 User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}
*/
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		auth.userDetailsService(inMemoryUserDetailsManager());
	}

	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	public InMemoryUserDetailsManager inMemoryUserDetailsManager()
	{
		List<UserDetails> userDetailsList = new ArrayList<>();
		userDetailsList.add(User.withUsername("user").password(passwordEncoder().encode("password"))
				.roles("USER").build());
		userDetailsList.add(User.withUsername("admin").password(passwordEncoder().encode("password"))
				.roles("ADMIN", "USER").build());
		return new InMemoryUserDetailsManager(userDetailsList);
	}
}
