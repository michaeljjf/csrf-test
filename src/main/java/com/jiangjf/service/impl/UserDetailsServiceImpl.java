package com.jiangjf.service.impl;

import com.jiangjf.model.User;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * @author jiangjf
 * @date 2022/1/25
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 使用数据库用户登录
        RowMapper<User> rowMapper = new BeanPropertyRowMapper<>(User.class);
        List<User> users = jdbcTemplate.query("select * from users where username=?", rowMapper, username);
        User user = DataAccessUtils.uniqueResult(users);
        if (user == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        System.out.println(user);
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList("admin");
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }
}
