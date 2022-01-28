package com.jiangjf.filter;

import com.google.code.kaptcha.Constants;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jiangjf
 * @date 2022/1/27
 */
public class CodeFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String uri = req.getServletPath();

        if ("/login".equals(uri) && "post".equalsIgnoreCase(req.getMethod())) {
            String sessionCode = req.getSession().getAttribute(Constants.KAPTCHA_SESSION_KEY).toString();
            String formCode = req.getParameter("code").trim();

            System.out.println(req.getSession().getAttribute(Constants.KAPTCHA_SESSION_KEY));

            if (StringUtils.isEmpty(formCode)) {
                throw new RuntimeException("验证码不能为空");
            }
            if (sessionCode.equalsIgnoreCase(formCode)) {
                System.out.println("验证通过");
            } else {
                throw new AuthenticationServiceException("验证码校验失败");
            }
        }

        chain.doFilter(request, response);
    }
}
