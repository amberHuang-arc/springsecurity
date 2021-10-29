package com.example.securingweb.controller;


import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;


@Controller
public class HelloController {
    @Autowired
    public InMemoryUserDetailsManager inMemoryUserDetailsManager;
    @Autowired
    public PasswordEncoder passwordEncoder;

    @GetMapping("/listAll")
    public String listAllUsers() {
        Field field = ReflectionUtils.findField(org.springframework.security.authentication.ProviderManager.class, "providers");
        ReflectionUtils.makeAccessible(field);
        List listOfProviders = (List) ReflectionUtils.getField(field, inMemoryUserDetailsManager);
        DaoAuthenticationProvider dao = (DaoAuthenticationProvider) listOfProviders.get(0);
        Field fieldUserDetailService = ReflectionUtils.findField(DaoAuthenticationProvider.class, "userDetailsService");
        ReflectionUtils.makeAccessible(fieldUserDetailService);
        InMemoryUserDetailsManager userDet = (InMemoryUserDetailsManager) (ReflectionUtils.getField(fieldUserDetailService, dao));
        Field usersMapField = ReflectionUtils.findField(InMemoryUserDetailsManager.class, "users");
        ReflectionUtils.makeAccessible(usersMapField);
        Map map = (Map) ReflectionUtils.getField(usersMapField, userDet);
        System.out.println(map);
        return map.entrySet().toString();
    }

    @GetMapping("adminCheck")
    public String checkUser(@RequestParam(name = "username") String username, Model model) {
        boolean flag = inMemoryUserDetailsManager.userExists(username);
        String result;
        if (flag) {
            result = "\"" + username + "\" existed!";
            result += "roles: " + inMemoryUserDetailsManager.loadUserByUsername(username).getAuthorities();
        } else
            result = "\"" + username + "\" does not exist in InMemoryUserDetailsManager";

        model.addAttribute("result", result);
        return "adminCheckUser";
    }

//    @GetMapping("/user/{username}")
//    public String checkIfUserExists(@PathVariable("username") String username) {
//        boolean flag = inMemoryUserDetailsManager.userExists(username);
//        String result;
//        if (flag) {
//            result = "\"" + username + "\" existed in InMemoryUserDetailsManager";
//            result += "roles: " + inMemoryUserDetailsManager.loadUserByUsername(username).getAuthorities();
//        } else {
//            result = "\"" + username + "\" does not exist in InMemoryUserDetailsManager";
//        }
//        return result;
//    }

    private boolean ifUserExists(String username) {
        return inMemoryUserDetailsManager.userExists(username);
    }


    @PostMapping("/adminAdd")
    public String addUser(@RequestParam(name = "username") String username, @RequestParam(name = "password") String password,
                          @RequestParam(name = "role") String role, Model model) {
        System.out.println("  ### need add a user: " + username + "/" + password + "/" + role);
        if (ifUserExists(username)) {
            model.addAttribute("userExists", true);
        } else {
            String roleStr = role.toUpperCase();
            if (!roleStr.startsWith("ROLE_")) {
                roleStr = "ROLE_" + roleStr;
            }
            ArrayList<GrantedAuthority> grantedAuthoritiesList = new ArrayList<>();
            grantedAuthoritiesList.add(new SimpleGrantedAuthority(roleStr));
            inMemoryUserDetailsManager
                    .createUser(new User(username, passwordEncoder.encode(password), grantedAuthoritiesList));
            model.addAttribute("result", "user " + username + " was added");
        }
        return "adminAddUser";

    }

    @PostMapping("/adminUpdate")
    public String updateUser(@RequestParam(name = "username") String username, @RequestParam(name = "password") String password,
                             @RequestParam(name = "role") String role, Model model) {

        ArrayList<GrantedAuthority> grantedAuthoritiesList = new ArrayList<>();
        grantedAuthoritiesList.add(new SimpleGrantedAuthority(role));
        inMemoryUserDetailsManager
                .updateUser(new User(username, passwordEncoder.encode(password), grantedAuthoritiesList));
        return "adminUpdateUser";
    }

//    @GetMapping("/adminCheck/create/{username}/{password}/{role}")
//    public String createUser(@PathVariable("username") String username, @PathVariable("password") String password,
//                             @PathVariable("role") String role) {
//        ArrayList<GrantedAuthority> grantedAuthoritiesList = new ArrayList<>();
//        grantedAuthoritiesList.add(new SimpleGrantedAuthority(role));
//        inMemoryUserDetailsManager
//                .createUser(new User(username, passwordEncoder.encode(password), grantedAuthoritiesList));
//        return checkIfUserExists(username);
//    }
//
//    @GetMapping("/adminCheck/update/{username}/{password}/{role}")
//    public String updateUser2(@PathVariable("username") String username, @PathVariable("password") String password,
//                              @PathVariable("role") String role) {
//        ArrayList<GrantedAuthority> grantedAuthoritiesList = new ArrayList<>();
//        grantedAuthoritiesList.add(new SimpleGrantedAuthority(role));
//        inMemoryUserDetailsManager
//                .updateUser(new User(username, passwordEncoder.encode(password), grantedAuthoritiesList));
//        return checkIfUserExists(username);
//    }
//
//    @GetMapping("/adminCheck/delete/{username}")
//    public String deleteUser(@PathVariable("username") String username) {
//        inMemoryUserDetailsManager.deleteUser(username);
//        return checkIfUserExists(username);
//    }
}