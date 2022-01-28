package com.jiangjf.config;

import com.jiangjf.filter.CodeFilter;
import com.jiangjf.provider.MyAuthProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

/**
 * EnableWebSecurity 如果使用的是starter，则不需要这个注解，所以这里不需要
 * EnableGlobalMethodSecurity 支持方法级的权限验证
 *
 * @author jiangjf
 * @date 2022/1/25
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    MyAuthProvider myAuthProvider;

    @Resource
    UserDetailsService userDetailsService;

    @Bean
    PasswordEncoder getPasswordEncoder() {
        // 指定加密器
//        return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 基于内存存储的多用户
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(new BCryptPasswordEncoder().encode("user@123"))
                .roles("admin")
                .and()
                .withUser("user1")
                .password(new BCryptPasswordEncoder().encode("user@123"))
                .roles("user")
                .and()
                .withUser("user2")
                .password(new BCryptPasswordEncoder().encode("user@123"))
                .roles("admin", "user")
                .and()
                .withUser("guest")
                .password(new BCryptPasswordEncoder().encode("user@123"))
                .roles("guest");

        // 自定义
//        auth.authenticationProvider(myAuthProvider);

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        System.out.println(new BCryptPasswordEncoder().encode("user@123"));
//        System.out.println(new BCryptPasswordEncoder().encode("user@123"));

        // 注意：csrf默认开启，这里登录时，需要传_csrf参数
        http.csrf().csrfTokenRepository(new HttpSessionCsrfTokenRepository());

        http.addFilterBefore(new CodeFilter(), UsernamePasswordAuthenticationFilter.class);

        // 设置授权才能访问
        http
                .authorizeRequests().antMatchers("/img/**", "/js/**").permitAll()
                .and()
                .authorizeRequests().antMatchers("/kaptcha").permitAll()
                .and()
                .authorizeRequests().anyRequest().authenticated();

        // 登录相关
        http.formLogin()
                // 自定义用户名、密码的提交参数
//                .usernameParameter("username")
//                .passwordParameter("password")
                .loginPage("/login.html")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/", true)
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        // 统计失败次数，失败多少次可以先锁定用户，一段时间后才可能再次登录
                        e.printStackTrace();
                        request.getSession().setAttribute("msg", e.getMessage());
                        response.sendRedirect("/login.html");
                    }
                })
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 配置了successHandler后，defaultSuccessUrl会失效
                        // 登录成功后的业务
//                        request.getRequestDispatcher("").forward(request, response);

                        Enumeration<String> attributeNames = request.getSession().getAttributeNames();
                        while (attributeNames.hasMoreElements()) {
                            String element = attributeNames.nextElement();
                            System.out.println("key:" + element);
                            System.out.println("value:" + request.getSession().getAttribute(element));
                        }

                        response.sendRedirect("/");
                    }
                })
                .permitAll();

        // 可以在LogoutHandler做退出登录的业务，可以有多个LogoutHandler
        http.logout().addLogoutHandler(new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                System.out.println("退出1");
            }
        }).addLogoutHandler(new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                System.out.println("退出2");
            }
        });
        // 使用MyAuthProvider来实现
//        http.userDetailsService(userService);

        // 使用记住我功能，需要设置userDetailsService
        http.rememberMe().userDetailsService(userDetailsService);

        /**
         * maximumSessions(1) 防止用户重复登录，限制只能有一个会话，后登录的用户会踢前面登录的用户下来
         * 设置maxSessionsPreventsLogin(true)后，后面相同用户不允许再登录，会提示Maximum sessions of 1 for this principal exceeded
         */
        http.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true);
    }

    /**
     * 设置了http.sessionManagement().maximumSessions(1)后，不加这个bean好像也能正常工作
     *
     * @return
     */
    @Bean
    HttpSessionEventPublisher getHttpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

//    /**
//     * 角色继承
//     *
//     * @return
//     */
//    @Bean
//    RoleHierarchy roleHierarchy() {
//        RoleHierarchyImpl impl = new RoleHierarchyImpl();
//        impl.setHierarchy("ROLE_admin > ROLE_user");
//        return impl;
//    }
}
