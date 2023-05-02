package com.maher.section345.controllers;


import com.maher.section345.entities.Equipe;
import com.maher.section345.service.EquipeService;
import org.apache.coyote.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin
public class EquipeRestController {

    @Autowired
    EquipeService equipeService;

    @RequestMapping(method= RequestMethod.GET)
    public List<Equipe> getAllEquipes(){
        return equipeService.getAllEquipes();
    }
    @RequestMapping(value="/{id}" ,method = RequestMethod.GET )
    public Equipe getEquipe(@PathVariable("id") long id){
        return equipeService.getEquipe(id);
    }
    @RequestMapping(method = RequestMethod.POST)
    public Equipe saveEquipe(@RequestBody Equipe e){
        return equipeService.saveEquipe(e);
    }
    @RequestMapping(method = RequestMethod.PUT)
    public Equipe updateEquipe(@RequestBody Equipe e)
    {
        return equipeService.updateEquipe(e);

    }
    @RequestMapping(value="/{id}",method = RequestMethod.DELETE)
    public void  deleteEquipe(@PathVariable("id") long id)
    {
         equipeService.deleteEquipeById(id);

    }
    @RequestMapping(value="/eqlg/{idLeg}",method = RequestMethod.GET)
    public List<Equipe> getProduitsByCatId(@PathVariable("idLeg") Long idLeg) {
        return equipeService.findByLeagueIdLeg(idLeg);
    }

}
