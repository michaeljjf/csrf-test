package com.jiangjf.controller;

import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.Producer;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.util.Random;

/**
 * @author jiangjf
 * @date 2022/1/25
 */
@Controller
public class IndexController {

    @RequestMapping("/login.html")
    public String login(Model model, HttpServletRequest request) {
        System.out.println("login");
        Object msg = request.getSession().getAttribute("msg");
        System.out.println("msg：" + msg);
        model.addAttribute("msg", msg);
        return "login";
    }

    @RequestMapping
    public String index() {
        System.out.println("index");
        return "index";
    }

    /**
     * 单个角色
     *
     * @return
     */
    @Secured("ROLE_admin")
    @GetMapping("/admin/index")
    @ResponseBody
    public String adminIndex() {
        return "admin index";
    }

    /**
     * 其中一个角色（多个角色）
     *
     * @return
     */
    @Secured({"ROLE_admin", "ROLE_user"})
    @GetMapping("/admin/index2")
    @ResponseBody
    public String adminIndex2() {
        return "admin index2";
    }

    /**
     * 使用PreAuthorize注释，hasAnyRole 或的关系
     *
     * @return
     */
    @PreAuthorize("hasAnyRole('ROLE_admin', 'ROLE_user')")
    @GetMapping("/admin/index3")
    @ResponseBody
    public String adminIndex3() {
        return "admin index3";
    }

    /**
     * 使用PreAuthorize注释，需要同时有两个角色才能访问的方法
     *
     * @return
     */
    @PreAuthorize("hasRole('ROLE_admin') AND hasRole('ROLE_user')")
    @GetMapping("/admin/index4")
    @ResponseBody
    public String adminIndex4() {
        return "admin index4";
    }

    /**
     * PostAuthorize根据返回值来决定是否有权限访问
     *
     * @return
     */
    @PostAuthorize("returnObject==1")
    @GetMapping("/admin/index5")
    @ResponseBody
    public int adminIndex5() {
        int random = new Random().nextInt(2);
        System.out.println("random：" + random);
        return random;
    }

    @Resource
    Producer captchaProducer;

    @GetMapping("/kaptcha")
    public void getKaptchaImage(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/jpeg");
        String capText = captchaProducer.createText();

        session.setAttribute(Constants.KAPTCHA_SESSION_KEY, capText);
        BufferedImage bi = captchaProducer.createImage(capText);
        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(bi, "jpg", out);
        try {
            out.flush();
        } finally {
            out.close();
        }
    }

}
