package com.maher.section345.controllers;

import com.maher.section345.entities.Equipe;
import com.maher.section345.entities.League;
import com.maher.section345.service.EquipeService;
import com.maher.section345.service.LeagueService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

@Controller
public class EquipeController {

    @Autowired
    EquipeService equipeService;

    @Autowired
    LeagueService leagueService;
    @RequestMapping("/showCreate")
    public String showCreate(ModelMap modelMap)
    {
        List<League> leagues = leagueService.getAllLeagues();
        modelMap.addAttribute("leagues", leagues);


        modelMap.addAttribute("equipe", new Equipe());
        modelMap.addAttribute("mode", "new");

        return "formEquipe";
    }


    @RequestMapping("/saveEquipe")
    public String saveEquipe(@Valid Equipe equipe,
                             BindingResult bindingResult,
                             RedirectAttributes redirectAttributes,

                             @RequestParam (name="size", defaultValue = "2") int size) {

        if (bindingResult.hasErrors()) return "formEquipe";
        equipeService.saveEquipe(equipe);

        // Calculate the total number of pages based on the number of teams and the page size.
        int totalEquipePages = (int) Math.ceil((double) equipeService.countEquipes() /size);
        int lastPage = totalEquipePages - 1;

        redirectAttributes.addAttribute("page", lastPage);
        return "redirect:/ListeEquipe";
    }


    @RequestMapping("/ListeEquipe")
    public String ListeEquipe(ModelMap modelMap,
                                @RequestParam (name="page",defaultValue = "0") int page,
                                @RequestParam (name="size", defaultValue = "2") int size)
    {
        List<League> leagues = leagueService.getAllLeagues();
        modelMap.addAttribute("leagues", leagues);
        Page <Equipe> equipes = equipeService.getAllEquipesParPage(page, size);
        modelMap.addAttribute("equipes", equipes);
        modelMap.addAttribute("pages", new int[equipes.getTotalPages()]);
        modelMap.addAttribute("currentPage", page);
        modelMap.addAttribute("size", size);
        return "ListeEquipe";


    }
    @RequestMapping("/supprimerEquipe")
    public String supprimerEquipe(@RequestParam("id") Long id,
                                ModelMap modelMap,
                                @RequestParam (name="page",defaultValue = "0") int page,
                                @RequestParam (name="size", defaultValue = "2") int size)
    {
        equipeService.deleteEquipeById(id);
        Page <Equipe> equipes = equipeService.getAllEquipesParPage(page, size);
        modelMap.addAttribute("equipes", equipes);
        modelMap.addAttribute("pages", new int[equipes.getTotalPages()]);
        modelMap.addAttribute("currentPage", page);
        modelMap.addAttribute("size", size);
        return "ListeEquipe";
    }
    @RequestMapping("/modifierEquipe")
    public String modifierEquipe(@RequestParam("id") Long id,
                                  @RequestParam (name="page",defaultValue = "0") int page,


                                  ModelMap modelMap)
    {
        Equipe e = equipeService.getEquipe(id);
        List<League> leagues = leagueService.getAllLeagues();
        modelMap.addAttribute("leagues", leagues);
        modelMap.addAttribute("equipe", e);
        modelMap.addAttribute("leagues", leagues);
        modelMap.addAttribute("selectedLeague", e.getLeague());
        modelMap.addAttribute("currentPage", page);


        modelMap.addAttribute("mode", "edit");

        return "formEquipe";
    }
    @RequestMapping("/updateEquipe")
    public String updateEquipe(@ModelAttribute("equipe") Equipe equipe,
                               @RequestParam("date") String date,
                               @RequestParam("idEquipe") Long id,
                               @RequestParam("page") int page,
                                 @RequestParam("size") int size,
                               ModelMap modelMap) throws
            ParseException
    {
//conversion de la date
        SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
        Date dateCreation = dateformat.parse(String.valueOf(date));
        equipe.setDateFound(dateCreation);
        equipeService.updateEquipe(equipe);
        List <Equipe> equipes = equipeService.getAllEquipes();
        modelMap.addAttribute("equipes", equipes);
        modelMap.addAttribute("pages", page);
        modelMap.addAttribute("currentPage", page);
        modelMap.addAttribute("size", size);
        return "ListeEquipe";
    }


}
