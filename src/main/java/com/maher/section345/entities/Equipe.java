package com.maher.section345.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;
import org.springframework.format.annotation.DateTimeFormat;

import javax.xml.crypto.Data;
import java.util.Date;

@Entity
public class Equipe {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idEquipe;
    @NotNull
    @Size(min = 4,max = 15)
    private String nomEquipe;
    @NotNull
    @Size(min = 4,max = 15)

    private String paysEquipe;
    @Temporal(TemporalType.DATE)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    @PastOrPresent

    private Date dateFound;
    @ManyToOne
    private League league;

    public Equipe() {
        super();
    }
    public Equipe(String nomEquipe, String paysEquipe) {
        super();
        this.nomEquipe = nomEquipe;
        this.paysEquipe = paysEquipe;
    }
    public Long getIdEquipe() {
        return idEquipe;
    }
    public void setIdEquipe(Long idEquipe) {
        this.idEquipe = idEquipe;
    }
    public String getNomEquipe() {
        return nomEquipe;
    }
    public void setNomEquipe(String nomEquipe) {
        this.nomEquipe = nomEquipe;
    }
    public String getPaysEquipe() {
        return paysEquipe;
    }
    public void setPaysEquipe(String paysEquipe) {
        this.paysEquipe = paysEquipe;
    }
    public void setDateFound(Date dateFound) {
        this.dateFound = dateFound;
    }
    public Date getDateFound() {
        return dateFound;
    }
    public League getLeague() {
        return league;
    }
    public void setLeague(League league) {
        this.league = league;
    }
    @Override
    public String toString() {
        return "Equipe [idEquipe=" + idEquipe + ", nomEquipe=" + nomEquipe + ", paysEquipe=" + paysEquipe + "]";
    }




}
