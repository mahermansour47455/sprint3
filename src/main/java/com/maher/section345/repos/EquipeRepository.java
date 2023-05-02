package com.maher.section345.repos;

import com.maher.section345.entities.Equipe;
import com.maher.section345.entities.League;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;



import java.util.List;



@RepositoryRestResource(path = "rest")
public interface EquipeRepository extends JpaRepository<Equipe, Long> {

    List<Equipe> findByNomEquipe(String nom);
    List<Equipe>findByNomEquipeContains(String nom);
    @Query("select p from Equipe p where p.league = ?1")
    List<Equipe> findByLeague (League l);
    List<Equipe> findByLeagueIdLeg(Long id);

    List<Equipe> findByOrderByNomEquipeAsc();
    @Query("select count(p) from Equipe p")
    int  countEquipes();



}
