package org.xbdframework.sample.sso.oa.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/system")
public class SystemController {

    @Value("${spring.application.name}")
    private String name;

    @Value("${spring.application.version}")
    private String version;

    @Value("${crm.profile-uri}")
    public String crmProfileUri;

    @RequestMapping("/profile")
    public Object profile(Model model) {
        model.addAttribute("name", name);
        model.addAttribute("version", version);
        model.addAttribute("crmProfileUri", crmProfileUri);

        return "/system/profile";
    }

}
