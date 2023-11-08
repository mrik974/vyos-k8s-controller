package com.partitio.vyos.controller;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.resteasy.reactive.ClientWebApplicationException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import io.fabric8.kubernetes.api.model.ServicePort;
import io.quarkus.arc.Lock;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response;

@Singleton
public class VyOSController {

    @ConfigProperty(name = "vyos.api-key")
    private String vyOSApiKey;

    @ConfigProperty(name = "vyos.rule-start", defaultValue = "200")
    private Integer ruleStart;

    @ConfigProperty(name = "vyos.rule-end", defaultValue = "400")
    private Integer ruleEnd;

    @ConfigProperty(name = "vyos.firewall-ruleset-name", defaultValue = "OUTSIDE-IN")
    private String firewallRulesetName;

    @ConfigProperty(name = "vyos.wan-interface", defaultValue = "eth0")
    private String wanInterface;

    @ConfigProperty(name = "vyos.lan-interface", defaultValue = "eth1")
    private String lanInterface;

    @ConfigProperty(name = "vyos.available-ip-range")
    private String ipRange;

    @ConfigProperty(name = "vyos.public-ip-netmask", defaultValue = "28")
    private Integer netmask;

    @ConfigProperty(name = "vyos.private-network")
    private String privateNetwork;

    @Inject
    @RestClient
    private VyOSQuerier querier;

    private ObjectMapper mapper = new ObjectMapper();

    private List<String> allConfigurableIPs;
    private List<Integer> allPossibleRuleNumbers;
    private List<Integer> allPossibleHairpinRuleNumbers;

    // 0 : rulesetname, 1 : rulenumber, 2 : IP address, 3 : port, 4 : name
    private static final String createFirewallRuleCommand = "['{'\"op\":\"set\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\",\"action\",\"accept\"]'}','{'\"op\":\"set\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\",\"destination\",\"address\",\"{2}\"]'}','{'\"op\":\"set\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\",\"destination\",\"port\",\"{3,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\",\"protocol\",\"tcp\"]'}','{'\"op\":\"set\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\",\"description\",\"Auto Kube Firewall rule for {4}, IP : {2}, port : {3,number,#}\"]'}']";
    // 0 : rulenumber, 1 : port, 2 : destinationaddress, 3 : translationaddress, 4 :
    // inbound-interface, 5 : service name
    private static final String createDestinationNatRuleCommand = "['{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"destination\",\"port\",\"{1,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"destination\",\"address\",\"{2}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"translation\",\"address\",\"{3}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"translation\",\"port\",\"{1,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"inbound-interface\",\"{4}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"protocol\",\"tcp\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"description\",\"Auto Kube Nat rule for {5}, IP : {3}, port : {1,number,#}, publicIP : {2}\"]'}']";
    // 0 : rulenumber, 1 : port, 2 : destinationaddress, 3 : translationaddress, 4 :
    // inbound-interface, 5 : service name
    private static final String createHairpinDestinationNatRuleCommand = "['{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"destination\",\"port\",\"{1,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"destination\",\"address\",\"{2}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"translation\",\"address\",\"{3}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"translation\",\"port\",\"{1,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"inbound-interface\",\"{4}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"protocol\",\"tcp\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\",\"description\",\"Auto Kube Hairpin Nat rule for {5}, IP : {3}, port : {1,number,#}, publicIP : {2}\"]'}']";
    // 0 : rulenumber, 1 : privatenetwork (192.168.199.0/24), 2 : port, 3 :
    // destinationaddress, 4 : outbound-interface, 5 : service name
    private static final String createHairpinSourceNatRuleCommand = "['{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"source\",\"address\",\"{1}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"destination\",\"port\",\"{2,number,#}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"destination\",\"address\",\"{3}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"translation\",\"address\",\"masquerade\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"outbound-interface\",\"{4}\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"protocol\",\"tcp\"]'}','{'\"op\":\"set\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\",\"description\",\"Auto Kube Hairpin Nat Source rule for {5}, IP : {3}, port : {2,number,#}, private network : {1}\"]'}']";
    // 0 : interface, 1 : address
    private static final String addIPAddresssCommand = "'{'\"op\": \"set\", \"path\": [\"interfaces\", \"ethernet\", \"{0}\", \"address\", \"{1}\"]'}'";
    private static final String deleteIPAddresssCommand = "'{'\"op\": \"delete\", \"path\": [\"interfaces\", \"ethernet\", \"{0}\", \"address\", \"{1}/{2,number,#}\"]'}'";
    private static final String deleteFirewallRuleCommand = "['{'\"op\":\"delete\",\"path\":[\"firewall\",\"name\",\"{0}\",\"rule\",\"{1,number,#}\"]'}']";
    private static final String deleteSourceNatRuleCommand = "['{'\"op\":\"delete\",\"path\":[\"nat\",\"source\",\"rule\",\"{0,number,#}\"]'}']";
    private static final String deleteDestinationNatRuleCommand = "['{'\"op\":\"delete\",\"path\":[\"nat\",\"destination\",\"rule\",\"{0,number,#}\"]'}']";

    @PostConstruct
    private void postConstruct() {
        // Build all IP list from available ip range
        this.allConfigurableIPs = buildAvailableIPs();
        this.allPossibleRuleNumbers = buildPossibleRuleNumbers(false);
        this.allPossibleHairpinRuleNumbers = buildPossibleRuleNumbers(true);
    }

    @Lock
    public VyOSResults createRules(String ip, String name, List<ServicePort> ports) throws Exception {
        VyOSResults results = new VyOSResults();
        // We have to create a set of rules for each port
        // First we have to check if an IP is still available on VyOS to redirect the
        // traffic
        String publicIPAddressCIDR = getNextAvailableAddress();
        String publicIPAddress = publicIPAddressCIDR.split("/", 0)[0];
        results.publicIP = publicIPAddress;
        // Next, for each port...
        // we have to get the existing rules to make sure of the number
        for (ServicePort port : ports) {
            Integer nextFirewallRuleNumber = getNextAvailableFirewallRuleNumber(allPossibleRuleNumbers);
            Integer nextDestinationNatRuleNumber = getNextAvailableDestinationNatRuleNumber(allPossibleRuleNumbers);
            Integer nextHairpinSourceNatRuleNumber = getNextAvailableSourceNatRuleNumber(allPossibleHairpinRuleNumbers);
            Integer nextHairpinDestinationNatRuleNumber = getNextAvailableSourceNatRuleNumber(
                    allPossibleHairpinRuleNumbers);

            // And once we have them, create the rules HERE
            // Can't create them elsewhere, the numbers won't be OK...
            createFirewallRule(firewallRulesetName, port.getPort(), ip,
                    nextFirewallRuleNumber, name);
            createDestinationNatRule(publicIPAddress, ip, port.getPort(), wanInterface,
                    nextDestinationNatRuleNumber, name);
            createHairpinDestinationNatRule(publicIPAddress, ip, port.getPort(),
                    lanInterface, nextHairpinDestinationNatRuleNumber, name);
            createHairpinSourceNatRule(ip, port.getPort(), lanInterface, privateNetwork, nextHairpinSourceNatRuleNumber,
                    name);
            // Once rules are created, update the results
            results.firewallRules.put(port.getPort(), nextFirewallRuleNumber);
            results.natRules.put(port.getPort(), nextDestinationNatRuleNumber);
            results.hairpinNatDestinationRules.put(port.getPort(), nextHairpinDestinationNatRuleNumber);
            results.hairpinNatSourceRules.put(port.getPort(), nextHairpinSourceNatRuleNumber);
        }
        // Then create the IP address
        createIPAddress(publicIPAddressCIDR, wanInterface);
        // Then finish filling the results object and return it
        results.publicIP = publicIPAddress;
        return results;
    }

    private void createHairpinSourceNatRule(String ip, Integer port,
            String outboundInterface, String sourceNetwork, Integer ruleNumber, String serviceName) {
        String command = MessageFormat.format(createHairpinSourceNatRuleCommand, ruleNumber, sourceNetwork, port, ip,
                outboundInterface, serviceName);
        System.out.println(command);
        querier.configure(vyOSApiKey, command);
    }

    private void createHairpinDestinationNatRule(String destinationAddress,
            String translationAddress,
            Integer port, String inboundInterface, Integer ruleNumber, String serviceName) {
        String command = MessageFormat.format(createHairpinDestinationNatRuleCommand, ruleNumber, port, destinationAddress,
                translationAddress, inboundInterface, serviceName);
        System.out.println(command);
        querier.configure(vyOSApiKey, command);
    }

    private void createDestinationNatRule(String destinationAddress, String translationAddress,
            Integer port, String inboundInterface, Integer natRuleNumber, String serviceName) {
        String command = MessageFormat.format(createDestinationNatRuleCommand, natRuleNumber, port, destinationAddress,
                translationAddress, inboundInterface, serviceName);
        System.out.println(command);
        querier.configure(vyOSApiKey, command);
    }

    private void createFirewallRule(String firewallRulesetName, Integer port,
            String privateIP, Integer firewallRuleNumber, String serviceName) {
        String command = MessageFormat.format(createFirewallRuleCommand, firewallRulesetName, firewallRuleNumber,
                privateIP, port, serviceName);
        System.out.println(command);
        querier.configure(vyOSApiKey, command);
    }

    private void createIPAddress(String publicIPAddress, String wanInterface) {
        String command = MessageFormat.format(addIPAddresssCommand, wanInterface, publicIPAddress);
        System.out.println(command);
        querier.configure(vyOSApiKey, command);
    }

    private Integer getNextAvailableFirewallRuleNumber(List<Integer> allPossibleNumbers)
            throws JsonMappingException, JsonProcessingException {
        Response response;
        try {
            response = querier.getConfiguration(vyOSApiKey,
                    "{\"op\": \"showConfig\", \"path\": [\"firewall\", \"name\", \"" + firewallRulesetName
                            + "\"]}");
        } catch (ClientWebApplicationException e) {
            // Status code 400 here means there's no rule in the configuration yet
            if (e.getMessage().startsWith("Received: 'Bad Request, status code 400'", 0)) {
                return allPossibleNumbers.stream().findFirst().orElseThrow();
            }
            throw e;
        }
        String entity = response.readEntity(String.class);
        JsonNode rules = mapper.readTree(entity).get("data").get("rule");
        List<Integer> keys = new ArrayList<>();
        Iterator<String> iterator = rules.fieldNames();
        iterator.forEachRemaining(e -> keys.add(Integer.parseInt(e)));
        return allPossibleNumbers.stream().filter(number -> !keys.contains(number)).findFirst().orElseThrow();
    }

    private Integer getNextAvailableDestinationNatRuleNumber(List<Integer> allPossibleNumbers)
            throws JsonMappingException, JsonProcessingException {
        Response response;
        try {
            response = querier.getConfiguration(vyOSApiKey,
                    "{\"op\": \"showConfig\", \"path\": [\"nat\", \"destination\"]}");
        } catch (ClientWebApplicationException e) {
            // Status code 400 here means there's no rule in the configuration yet
            if (e.getMessage().startsWith("Received: 'Bad Request, status code 400'", 0)) {
                return allPossibleNumbers.stream().findFirst().orElseThrow();
            }
            throw e;
        }
        String entity = response.readEntity(String.class);
        if (response.getStatus() == 400) {
            String errorString = mapper.readTree(entity).get("data").asText();
            System.out.println(errorString);
        }
        JsonNode rules = mapper.readTree(entity).get("data").get("rule");
        List<Integer> keys = new ArrayList<>();
        Iterator<String> iterator = rules.fieldNames();
        iterator.forEachRemaining(e -> keys.add(Integer.parseInt(e)));
        return allPossibleNumbers.stream().filter(number -> !keys.contains(number)).findFirst().orElseThrow();
    }

    private Integer getNextAvailableSourceNatRuleNumber(List<Integer> allPossibleNumbers)
            throws JsonMappingException, JsonProcessingException {
        Response response;
        try {
            response = querier.getConfiguration(vyOSApiKey,
                    "{\"op\": \"showConfig\", \"path\": [\"nat\", \"source\"]}");
        } catch (ClientWebApplicationException e) {
            // Status code 400 here means there's no rule in the configuration yet
            if (e.getMessage().startsWith("Received: 'Bad Request, status code 400'", 0)) {
                return allPossibleNumbers.stream().findFirst().orElseThrow();
            }
            throw e;
        }
        String entity = response.readEntity(String.class);
        if (response.getStatus() == 400) {
            String errorString = mapper.readTree(entity).get("data").asText();
            System.out.println(errorString);
        }
        JsonNode rules = mapper.readTree(entity).get("data").get("rule");
        List<Integer> keys = new ArrayList<>();
        Iterator<String> iterator = rules.fieldNames();
        iterator.forEachRemaining(e -> keys.add(Integer.parseInt(e)));
        return allPossibleNumbers.stream().filter(number -> !keys.contains(number)).findFirst().orElseThrow();
    }

    private String getNextAvailableAddress() throws JsonMappingException, JsonProcessingException {
        Response response = querier.getConfiguration(vyOSApiKey,
                "{\"op\": \"showConfig\", \"path\": [\"interfaces\", \"ethernet\", \"" + wanInterface
                        + "\", \"address\"]}");
        String entity = response.readEntity(String.class);
        JsonNode actualResponse = mapper.readTree(entity);
        ArrayNode addressNodes = (ArrayNode) actualResponse.get("data").get("address");
        List<String> addresses = new ArrayList<>(addressNodes.size());
        addressNodes.forEach(node -> addresses.add(node.asText()));
        // Now we have the addresses we need to compare with the available IPs and
        // retrieve the first available
        return allConfigurableIPs.stream().map(ip -> ip + "/" + netmask)
                .filter(ip -> !addresses.contains(ip))
                .findFirst()
                .orElseThrow();
    }

    private List<String> buildAvailableIPs() {
        // Dirty work
        // First we get beginning and ending
        String firstIP = this.ipRange.split("-")[0];
        String lastIP = this.ipRange.split("-")[1];
        String[] firstIPStrings = firstIP.split("\\.");
        String[] lastIPStrings = lastIP.split("\\.");
        // then we compare if the first 3 bytes are the same
        boolean firstByte = firstIPStrings[0].equals(lastIPStrings[0]);
        boolean secondByte = firstIPStrings[1].equals(lastIPStrings[1]);
        boolean thirdByte = firstIPStrings[2].equals(lastIPStrings[2]);

        // If any of these booleans is false, throw an exception
        if (!firstByte || !secondByte || !thirdByte) {
            throw new RuntimeException("IP Range is too big, check vyos.available-ip-range");
        }
        // Now we can build the list.
        String firstByteString = firstIPStrings[0];
        String secondByteString = firstIPStrings[1];
        String thirdByteString = firstIPStrings[2];

        Integer fourthByteBeginning = Integer.parseUnsignedInt(firstIPStrings[3]);
        Integer fourthByteEnd = Integer.parseUnsignedInt(lastIPStrings[3]);
        List<Integer> range = IntStream.rangeClosed(fourthByteBeginning, fourthByteEnd)
                .boxed().collect(Collectors.toList());
        // Now we have the list we have to put all of them together
        return range.stream().map(t -> t.toString()).map(s -> {
            return firstByteString + "." + secondByteString + "." + thirdByteString + "." + s;
        }).collect(Collectors.toList());
    }

    private List<Integer> buildPossibleRuleNumbers(boolean odd) {
        List<Integer> availableRules = new ArrayList<>();
        if (odd) {
            for (int i = ruleStart; i <= ruleEnd; i++) {
                if (i % 2 != 0) {
                    availableRules.add(i);
                }
            }
        } else {
            for (int i = ruleStart; i <= ruleEnd; i++) {
                if (i % 2 == 0) {
                    availableRules.add(i);
                }
            }
        }
        return availableRules;
    }

    public void deleteRules(String iPaddress, Map<String, Integer> firewallRules,
            Map<String, Integer> destinationNatRules, Map<String, Integer> hairpinDestinationNatRules,
            Map<String, Integer> hairpinSourceNatRules) {
        // Delete IP
        String deleteIPCommand = MessageFormat.format(deleteIPAddresssCommand, wanInterface, iPaddress, netmask);
        System.out.println(deleteIPCommand);
        querier.configure(vyOSApiKey, deleteIPCommand);
        // Delete firewall
        firewallRules.forEach((key, value) -> {
            String deleteFirewallCommand = MessageFormat.format(deleteFirewallRuleCommand, firewallRulesetName, value);
            querier.configure(vyOSApiKey, deleteFirewallCommand);
        });
        destinationNatRules.forEach((key, value) -> {
            String deleteDestinationNatCommand = MessageFormat.format(deleteDestinationNatRuleCommand, value);
            querier.configure(vyOSApiKey, deleteDestinationNatCommand);
        });
        hairpinDestinationNatRules.forEach((key, value) -> {
            String deleteDestinationNatCommand = MessageFormat.format(deleteDestinationNatRuleCommand, value);
            querier.configure(vyOSApiKey, deleteDestinationNatCommand);
        });
        hairpinSourceNatRules.forEach((key, value) -> {
            String deleteSourceNatCommand = MessageFormat.format(deleteSourceNatRuleCommand, value);
            querier.configure(vyOSApiKey, deleteSourceNatCommand);
        });
    }
}