package danielh1307.oidcexample.ctrl;

import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import static java.lang.String.join;
import static java.util.stream.Collectors.toList;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@RestController
public class AdminController {

    @GetMapping("/secret/hello")
    public String getSecretHello() {
        return "Hello " + embrace(preferredUserName()) + ", you have granted authorities " + embrace(commaSeparatedGrantedAuthorities()) + " and you have resource access roles " + embrace(commaSeparatedResourceAccessRoles());
    }

    private String preferredUserName() {
        AccessToken token = ((SimpleKeycloakAccount) getContext().getAuthentication().getDetails()).getKeycloakSecurityContext().getToken();

        return token.getPreferredUsername();
    }

    private String commaSeparatedGrantedAuthorities() {
        Collection<? extends GrantedAuthority> authorities = getContext().getAuthentication().getAuthorities();
        List<String> grantedAuthorities = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());
        return join(",", grantedAuthorities);
    }

    private String commaSeparatedResourceAccessRoles() {
        AccessToken token = ((SimpleKeycloakAccount) getContext().getAuthentication().getDetails()).getKeycloakSecurityContext().getToken();
        Set<String> resourceAccessRoles = token.getResourceAccess().get("spring-boot").getRoles();

        return join(",", resourceAccessRoles);
    }

    private String embrace(String s) {
        return "[" + s + "]";
    }

}


