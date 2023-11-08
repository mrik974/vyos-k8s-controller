package com.partitio.vyos.controller;

import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.informers.SharedInformerFactory;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.annotations.QuarkusMain;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

@QuarkusMain

public class KubernetesControllerApplication implements QuarkusApplication {

    @Inject
    private KubernetesClient client;

    @Inject
    private ServiceWatcher serviceWatcher;

    private SharedInformerFactory informerFactory = null;

    @Override
    public int run(String... args) throws Exception {
        informerFactory = client.informers();
        final var serviceHandler = informerFactory.sharedIndexInformerFor(Service.class, 30000);
        System.out.println("Connected to : " + client.getMasterUrl());
        serviceHandler.addEventHandler(serviceWatcher);
        informerFactory.startAllRegisteredInformers().get();
        System.out.println("Informer factory is watching : " + serviceHandler.isWatching());
        Quarkus.waitForExit();
        return 0;
    }

    void onShutDown(@Observes ShutdownEvent event) {
        informerFactory.stopAllRegisteredInformers();
    }

    public static void main(String... args) {
        Quarkus.run(KubernetesControllerApplication.class, args);
    }
}