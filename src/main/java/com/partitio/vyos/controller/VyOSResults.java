package com.partitio.vyos.controller;

import java.util.HashMap;
import java.util.Map;

public class VyOSResults {

    public String publicIP;
    public Map<Integer, Integer> natRules = new HashMap<>();
    public Map<Integer, Integer> hairpinNatSourceRules = new HashMap();
    public Map<Integer, Integer> hairpinNatDestinationRules = new HashMap<>();
    public Map<Integer, Integer> firewallRules = new HashMap<>();
    
}
