package com.maher.section345.entities;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;


import java.util.List;


@Entity


public class League {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idLeg;
    private String nomLeague;
    @JsonIgnore
    @OneToMany(mappedBy = "league")
    private List<Equipe> equipes;
    public  League() {
        super();
    }
    public League(String nomLeague) {
        super();
        this.nomLeague = nomLeague;
    }
       public Long getIdLeg() {
            return idLeg;
        }
    public void setIdLeg(Long idLeg) {
        this.idLeg = idLeg;
    }

    public String getNomLeague() {
        return nomLeague;
    }
    public void setNomLeague(String nomLeague) {
        this.nomLeague = nomLeague;
    }
    public List<Equipe> getEquipes() {
        return equipes;
    }
    public void setEquipes(List<Equipe> equipes) {
        this.equipes = equipes;
    }
    @Override
    public String toString() {
        return "League [idCat=" + idLeg + ", nomLeague=" + nomLeague + "]";
    }

}
