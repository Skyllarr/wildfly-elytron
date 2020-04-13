/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl._private;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.net.ssl.SSLParameters;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SSLParametersUtil {

    /**
     * Uses Gson to copy unknown SSLParameters' fields added in java 9 or later. Setter methods are used for fields available in Java 8.
     * @param original SSLParameters that should be applied to new instance
     * @return instance of SSLParameters with fields copied from original
     */
    public static SSLParameters copySSLParameters(SSLParameters original) {
        SSLParameters params;
        if (getVersion() > 8) {
            Gson gson = new GsonBuilder()
                    .setExclusionStrategies(new SSLParametersExclusionStrategy())
                    .create();
            String json = gson.toJson(original);
            params = gson.fromJson(json, SSLParameters.class);
        } else {
            params = new SSLParameters();
        }
        params.setProtocols(original.getProtocols());
        params.setCipherSuites(original.getCipherSuites());
        params.setUseCipherSuitesOrder(original.getUseCipherSuitesOrder());
        params.setServerNames(original.getServerNames());
        params.setSNIMatchers(original.getSNIMatchers());
        params.setAlgorithmConstraints(original.getAlgorithmConstraints());
        params.setEndpointIdentificationAlgorithm(original.getEndpointIdentificationAlgorithm());
        if (original.getWantClientAuth()) {
            params.setWantClientAuth(original.getWantClientAuth());
        } else if (original.getNeedClientAuth()) {
            params.setNeedClientAuth(original.getNeedClientAuth());
        }
        return params;
    }

    static class SSLParametersExclusionStrategy implements ExclusionStrategy {

        private Set<String> excludeFieldsSet = new HashSet<>(Arrays.asList(
                "cipherSuites",
                "protocols",
                "wantClientAuth",
                "needClientAuth",
                "identificationAlgorithm",
                "algorithmConstraints",
                "sniNames",
                "sniMatchers",
                "preferLocalCipherSuites"
        ));

        public boolean shouldSkipClass(Class<?> arg0) {
            return false;
        }

        public boolean shouldSkipField(FieldAttributes f) {

            return f.getDeclaringClass() == SSLParameters.class && excludeFieldsSet.contains(f.getName());
        }
    }

    private static int getVersion() {
        String version = System.getProperty("java.version");
        if(version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if(dot != -1) { version = version.substring(0, dot); }
        } return Integer.parseInt(version);
    }
}
