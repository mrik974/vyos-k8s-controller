package com.partitio.vyos.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.fabric8.kubernetes.api.model.LoadBalancerIngress;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServicePort;
import io.fabric8.kubernetes.api.model.ServiceSpec;
import io.fabric8.kubernetes.api.model.ServiceStatus;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.informers.ResourceEventHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class ServiceWatcher implements ResourceEventHandler<Service> {

    public static final String natRuleNumberAnnotation = "com.partitio.vyos.controller/nat-rule-numbers";
    public static final String hairpinNatSourceRuleNumberAnnotation = "com.partitio.vyos.controller/hairpin-nat-source-rule-numbers";
    public static final String hairpinNatDestinationRuleNumberAnnotation = "com.partitio.vyos.controller/hairpin-nat-destination-rule-numbers";
    public static final String firewallRuleNumberAnnotation = "com.partitio.vyos.controller/firewall-rule-numbers";
    public static final String publicIPAnnotation = "com.partitio.vyos.controller/public-ip-address";
    public static final String managedAnnotation = "com.partitio.vyos.controller/service-is-managed";

    @Inject
    private VyOSController vyosController;

    @Inject
    private KubernetesClient client;

    private ObjectMapper objectMapper = new ObjectMapper();

    private void checkAndReactOnAddedService(Service service) throws Exception {
        // Added service is only to find services added and configured while app was not
        // running.
        // If Service is of type LoadBalancer, has a public IP set and does not have
        // managed annotation
        // Create NAT, Firewall rules and annotate it
        if (isServiceManageable(service)) {
            Map<String, String> annotations = service.getMetadata().getAnnotations();
            if (annotations.containsKey(managedAnnotation) && annotations.get(managedAnnotation).equals("true")) {
                System.out.println("Service " + service.getMetadata().getName() + " on namespace "
                        + service.getMetadata().getNamespace() + " is already managed, ignoring...");
                return;
            }
            System.out.println("Service " + service.getMetadata().getName() + " on namespace "
                    + service.getMetadata().getNamespace() + " is not managed yet, reconciling...");
            createVyOSRulesAndAnnotateService(service);
        }
    }

    private boolean isServiceManageable(Service service) {
        ServiceSpec spec = service.getSpec();
        ServiceStatus status = service.getStatus();
        String serviceType = spec.getType();
        List<LoadBalancerIngress> loadBalancerIngresses = status.getLoadBalancer().getIngress();
        if (loadBalancerIngresses.isEmpty()) {
            return false;
        }
        LoadBalancerIngress ingress = status.getLoadBalancer().getIngress().get(0);

        String externalIP = Objects.requireNonNull(ingress.getIp());
        System.out.println("service type is " + serviceType + " for " + service.getMetadata().getName());
        System.out.println("service externalIP is empty for " + service.getMetadata().getName() + " : " + externalIP.isEmpty());
        return (serviceType.equals("LoadBalancer") && !externalIP.isEmpty());
    }

    private void createVyOSRulesAndAnnotateService(Service service) throws Exception {
        String ip = service.getStatus().getLoadBalancer().getIngress().get(0).getIp();
        String name = service.getMetadata().getNamespace() + "/" + service.getMetadata().getName();
        List<ServicePort> ports = service.getSpec().getPorts();
        VyOSResults result = vyosController.createRules(ip, name, ports);
        // Apply annotations to the service
        Map<String, String> annotations = new HashMap<>();
        annotations.put(publicIPAnnotation, result.publicIP);
        annotations.put(managedAnnotation, "true");
        annotations.put(firewallRuleNumberAnnotation, objectMapper.writeValueAsString(result.firewallRules));
        annotations.put(natRuleNumberAnnotation, objectMapper.writeValueAsString(result.natRules));
        annotations.put(hairpinNatDestinationRuleNumberAnnotation,
                objectMapper.writeValueAsString(result.hairpinNatDestinationRules));
        annotations.put(hairpinNatSourceRuleNumberAnnotation,
                objectMapper.writeValueAsString(result.hairpinNatSourceRules));
        service.getMetadata().setAnnotations(annotations);
        client.services().inNamespace(service.getMetadata().getNamespace()).resource(service).patch();
    }

    private void checkAndReactOnDeletedService(Service service) throws JsonMappingException, JsonProcessingException {
        // Check if service is annotated
        if (!service.getMetadata().getAnnotations().containsKey(managedAnnotation)) {
            return;
        }
        deleteServiceRules(service);
    }

    private void deleteServiceRules(Service service) throws JsonMappingException, JsonProcessingException {
        String IPaddress = service.getMetadata().getAnnotations().get(publicIPAnnotation);
        // For each annotation of the service, undo the vyos configuration

        Map<String, Integer> firewallRules = objectMapper
                .readValue(service.getMetadata().getAnnotations().get(firewallRuleNumberAnnotation), Map.class);
        Map<String, Integer> destinationNatRules = objectMapper
                .readValue(service.getMetadata().getAnnotations().get(natRuleNumberAnnotation), Map.class);
        Map<String, Integer> hairpinDestinationNatRules = objectMapper.readValue(
                service.getMetadata().getAnnotations().get(hairpinNatDestinationRuleNumberAnnotation), Map.class);
        Map<String, Integer> hairpinSourceNatRules = objectMapper.readValue(
                service.getMetadata().getAnnotations().get(hairpinNatSourceRuleNumberAnnotation), Map.class);

        vyosController.deleteRules(IPaddress, firewallRules, destinationNatRules, hairpinDestinationNatRules,
                hairpinSourceNatRules);
    }

    private void checkAndReactOnModifiedService(Service newService, Service oldService) throws Exception {
        boolean containsManagedAnnotation = newService.getMetadata().getAnnotations().containsKey(managedAnnotation);
        boolean isServiceManageable = isServiceManageable(newService);

        // If service is not manageable and doesn't have annotations, ignore
        if (!isServiceManageable && !containsManagedAnnotation) {
            System.out.println(
                    "Service " + newService.getMetadata().getName() + " on namespace is not interesting, ignoring");
            return;
        }

        // If Service is NOT manageable but has annotations
        // It means service type has been modified
        // Delete rules and annotations
        if (!isServiceManageable && containsManagedAnnotation) {
            System.out.println("Service " + newService.getMetadata().getName()
                    + " type has changed to not manageable, removing rules");
            deleteServiceRules(newService);
            deleteServiceAnnotations(newService);
        }

        // If Service is manageable
        // And if Service does not have managed annotation
        // Create NAT, Firewall rules and annotate it
        if (isServiceManageable && !containsManagedAnnotation) {
            System.out.println("Service " + newService.getMetadata().getName() + " on namespace "
                    + newService.getMetadata().getNamespace() + " is not managed yet, reconciling...");
            createVyOSRulesAndAnnotateService(newService);
        }

        // If Service is manageable
        // And if Service has managed annotations
        // It may mean service has been modified.
        // Compare publicIP, and ports with old service to see if it has changed.
        // IF CHANGED :
        // Use the annotations to delete existing rules and recreate them
        // Reannotate the service
        boolean servicesAlike = checkIfOldAndNewServiceAreAlike(oldService, newService);
        if (!servicesAlike) {
            deleteServiceRules(newService);
            createVyOSRulesAndAnnotateService(newService);
        }

    }

    private void deleteServiceAnnotations(Service newService) {
        Map<String, String> annotations = newService.getMetadata().getAnnotations();
        annotations.remove(managedAnnotation);
        annotations.remove(publicIPAnnotation);
        annotations.remove(firewallRuleNumberAnnotation);
        annotations.remove(natRuleNumberAnnotation);
        annotations.remove(hairpinNatDestinationRuleNumberAnnotation);
        annotations.remove(hairpinNatSourceRuleNumberAnnotation);
        client.services().inNamespace(newService.getMetadata().getNamespace()).resource(newService).patch();
    }

    private boolean checkIfOldAndNewServiceAreAlike(Service oldService, Service newService) {
        // Check privateIP
        // Check ports
        List<LoadBalancerIngress> loadBalancerIngresses = newService.getStatus().getLoadBalancer().getIngress();
        if (loadBalancerIngresses.isEmpty()) {
            return false;
        }
        String newIP = newService.getStatus().getLoadBalancer().getIngress().get(0).getIp();
        String oldIP = oldService.getStatus().getLoadBalancer().getIngress().get(0).getIp();
        boolean ipIsSame = newIP.equals(oldIP);
        boolean arePortsSame = newService.getSpec().getPorts().equals(oldService.getSpec().getPorts());
        return (ipIsSame && arePortsSame);
    }

    @Override
    public void onAdd(Service service) {
        try {
            checkAndReactOnAddedService(service);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onUpdate(Service newService, Service oldService) {
        System.out.println("service updatefound, name is " + newService.getMetadata().getName());
        try {
            checkAndReactOnModifiedService(newService, oldService);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onDelete(Service service, boolean deletedFinalStateUnknown) {
        System.out.println("service delete found, name is " + service.getMetadata().getName());
        try {
            checkAndReactOnDeletedService(service);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }
}
