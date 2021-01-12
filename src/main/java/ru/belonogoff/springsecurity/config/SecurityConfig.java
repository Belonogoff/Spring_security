package ru.belonogoff.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.belonogoff.springsecurity.security.JwtConfigurer;

@Configuration
@EnableWebSecurity // "включает" Spring Security
@EnableGlobalMethodSecurity(prePostEnabled = true) // по всему приложению Security прописанно над методами @PreAuthorize
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtConfigurer jwtConfigurer;

    public SecurityConfig(JwtConfigurer jwtConfigurer) {
        this.jwtConfigurer = jwtConfigurer;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception { // позволяет настраивать веб безопасность для определенных запросов
        http
                .csrf().disable()// отключение какой то безопасности
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // не использую больше сессии
                .and()
                .authorizeRequests()// необходимо авторизовать(Это строкой мы говорим предоставить разрешения для следующих url.) запрос следующим образом
                .antMatchers("/").permitAll() // любые пользователи получат доступ к "/" .antMatchers() - кто имеет доступ к определенному запросу
                .antMatchers("/api/v1/auth/login").permitAll()
                .anyRequest() // каждый запрос
                .authenticated() // разрешает доступ всем аутентифицированным пользователям
                .and() // и
                .apply(jwtConfigurer);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
