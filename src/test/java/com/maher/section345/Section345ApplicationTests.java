package com.maher.section345;

import com.maher.section345.entities.Equipe;
import com.maher.section345.entities.League;
import com.maher.section345.repos.EquipeRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class Section345ApplicationTests {
    @Autowired
    private EquipeRepository equipeRepository;


    @Test
    void contextLoads() {
    }
    @Test
    public void testCreateEquipe(){
        Equipe equipe = new Equipe("amer", "Espagne");
        equipeRepository.save(equipe);
    }
    @Test

    public void testFindByNomEquipe()
    {
        List<Equipe> prods = equipeRepository.findByNomEquipe("Real Madrid");
        for (Equipe p : prods)
        {
            System.out.println(p);
        }
    }
    @Test
    public void testFindByNomProduitContains ()
    {
        List<Equipe> prods=equipeRepository.findByNomEquipeContains("a");
        for (Equipe p : prods)
        {
            System.out.println(p);
        } }

    @Test
    public void testfindByLeague()
    {
        League l = new League();
        l.setIdLeg(1L);
        List<Equipe> prods=equipeRepository.findByLeague(l);
        for (Equipe p : prods)
        {
            System.out.println(p);
        } }
    @Test
    public void findByCategorieIdCat()
    {
        List<Equipe> prods=equipeRepository.findByLeagueIdLeg(1L);
        for (Equipe p : prods)
        {
            System.out.println(p);
        }
    }
    @Test
    public void testfindByOrderByNomEquipeAsc()
    {
        List<Equipe> prods=equipeRepository.findByOrderByNomEquipeAsc();
        for (Equipe p : prods)
        {
            System.out.println(p);
        }
    }



}
