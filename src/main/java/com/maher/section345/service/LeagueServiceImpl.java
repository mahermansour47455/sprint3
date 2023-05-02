package com.maher.section345.service;

import com.maher.section345.entities.League;
import com.maher.section345.repos.LeagueRepos;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LeagueServiceImpl implements LeagueService{

    @Autowired
    private LeagueRepos leagueRepos;
    @Override
    public List<League> getAllLeagues() {
        return leagueRepos.findAll();
    }
}
