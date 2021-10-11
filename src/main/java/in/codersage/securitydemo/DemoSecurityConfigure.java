package in.codersage.securitydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;


@Configuration
@EnableWebSecurity
@ComponentScan
public class DemoSecurityConfigure extends WebSecurityConfigurerAdapter {
    @Autowired
    DataSource dataSource;
    @Qualifier("userDetailsServiceImpl")
    @Autowired
    UserDetailsService userDetailsService;
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }

    @Autowired
    private CustomOAuth2UserService oauthUserService;

    @Autowired
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Autowired
    UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers("/registration").permitAll()
                    .antMatchers("/guest/**").hasRole("GUEST")
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/", "/login", "/oauth/**").permitAll()
                    .and()
                    .formLogin().loginPage("/showMyLoginPage").loginProcessingUrl("/authenticateTheUser").permitAll().and().logout().permitAll().and().exceptionHandling().accessDeniedPage("/access-denied")
                    .and()
                    .oauth2Login()
                    .loginPage("/showMyLoginPage")
                    .userInfoEndpoint()
                    .userService(oauthUserService).and().successHandler(new AuthenticationSuccessHandler() {
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            CustomOAuth2User oAuth2User  = (CustomOAuth2User) authentication.getPrincipal();
                            userService.processOAuthPostLogin(oAuth2User.getName());
                            System.out.println(oAuth2User.getName());
                            response.sendRedirect("/");
                        }
                    }).and().oauth2Login().loginPage("/showMyLoginPage").userInfoEndpoint().userService(oauthUserService).and().successHandler(new AuthenticationSuccessHandler() {
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            CustomOAuth2User oAuth2User  = (CustomOAuth2User) authentication.getPrincipal();
                            userService.processOAuthPostLogin2(oAuth2User.getName());
                            System.out.println(oAuth2User.getName());
                            response.sendRedirect("/");
                        }
                    });
//
//        http.oauth2Login()
//                .loginPage("/login")
//                .userInfoEndpoint()
//                .userService(oauthUserService)
//                .and()
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        CustomOAuth2User oAuth2User  = (CustomOAuth2User) authentication.getPrincipal();
//                        userService.processOAuthPostLogin(oAuth2User.getName());
//                        response.sendRedirect("/welcome");
//                    }
//                });
    }
}
