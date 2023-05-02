package com.maher.section345.service;

import com.maher.section345.entities.Equipe;
import com.maher.section345.entities.League;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.util.List;
public interface EquipeService {


    Equipe saveEquipe(Equipe e);
    Equipe updateEquipe(Equipe e);
    void deleteEquipe(Equipe e);
    void deleteEquipeById(Long id);
    Equipe getEquipe(Long id);
    List<Equipe> getAllEquipes();
    Page<Equipe> getAllEquipesParPage(int page, int size);
    List<Equipe> findByNomEquipe(String nom);
    List<Equipe> findByNomEquipeContains(String nom);
    List<Equipe> findByLeagueIdLeg (Long id);
    List<Equipe> findByOrderByNomEquipeAsc();
    List<Equipe>findByLeague(League l);


    int  countEquipes();
}
