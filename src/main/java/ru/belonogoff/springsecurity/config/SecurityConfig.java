package ru.belonogoff.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity // "включает" Spring Security
@EnableGlobalMethodSecurity(prePostEnabled = true) // по всему приложению Security прописанно над методами @PreAuthorize
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception { // позволяет настраивать веб безопасность для определенных запросов
        http
                .csrf().disable()// отключение какой то безопасности
                .authorizeRequests()// необходимо авторизовать(Это строкой мы говорим предоставить разрешения для следующих url.) запрос следующим образом
                .antMatchers("/").permitAll() // любые пользователи получат доступ к "/" .antMatchers() - кто имеет доступ к определенному запросу
                .anyRequest() // каждый запрос
                .authenticated() // разрешает доступ всем аутентифицированным пользователям
                .and() // и
                .formLogin()
                .loginPage("/auth/login").permitAll() // все имеют доступ к странице login
                .defaultSuccessUrl("/auth/success") // если все хорошо, переходим на данную страницу
                .and()
                .logout() // настройка logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
                .invalidateHttpSession(true)
                .clearAuthentication(true) // отчистить аунтификацию
                .deleteCookies("JSESSIONID") // удаление Cookies JSESSIONID
                .logoutSuccessUrl("/auth/login") // перенаправить на страницу
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    protected DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }
}
