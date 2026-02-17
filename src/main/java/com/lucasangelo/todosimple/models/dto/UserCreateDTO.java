package com.lucasangelo.todosimple.models.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class UserCreateDTO {

    @NotBlank
    @Size(min = 2, max = 100)
    private String username;

    @NotBlank
    @Size(min = 8, max = 60)
    private String password;

    // 1. Construtor Vazio (Obrigatório para o Spring/Jackson funcionar)
    public UserCreateDTO() {
    }

    // 2. Construtor com argumentos (Opcional, mas útil)
    public UserCreateDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // 3. Getters Corrigidos (O erro estava aqui)
    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    // 4. Setters (Necessários para receber os dados do JSON)
    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}