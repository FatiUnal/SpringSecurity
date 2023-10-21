package com.example.springsecurity2.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue
    private Integer id;
    private String firstNAme;
    private String lastName;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * kullanıcıların veya rollerin kimlik doğrulama işlemlerinde
     * nasıl kullanılıcaklarını tanımlamak GrantedAuthority tipinde nesneler oluşturulur
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    /**
     * HEsabın süresinin geçerli mi olup olmadıgını kontrol etmek için kullanılır
     * hesap süresi dolmuşsa false değeri döner.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Kullanıcının hesabının kilitli olup olmadığını kontrol etmek için kullanılır
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * kimlik bilgilerinin süresinin geçerli olup olmadıgını kontrol eder.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * hesabın etkin olup olmadıgını kontrol etmek için kullanılır
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getPassword(){
        return password;
    }
}
