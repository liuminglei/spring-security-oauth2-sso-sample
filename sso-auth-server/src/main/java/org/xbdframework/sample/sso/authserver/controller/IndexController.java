package org.xbdframework.sample.sso.authserver.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping
public class IndexController {

    @Value("${spring.application.name}")
    private String name;

    @Value("${spring.application.version}")
    private String version;

    @Value("${oa.profile-uri}")
    public String oaProfileUri;

    @Value("${crm.profile-uri}")
    public String crmProfileUri;

    @RequestMapping("/index")
    public String index(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        model.addAttribute("name", name);
        model.addAttribute("version", version);
        model.addAttribute("oaProfileUri", oaProfileUri);
        model.addAttribute("crmProfileUri", crmProfileUri);

        return "index";
    }

}
