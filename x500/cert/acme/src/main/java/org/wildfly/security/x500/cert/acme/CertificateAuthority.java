package org.wildfly.security.x500.cert.acme;

public class CertificateAuthority {

    private static final String DIRECTORY = "directory";
    private static final String LETS_ENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/" + DIRECTORY;
    private static final String LETS_ENCRYPT_URL = "https://acme-v02.api.letsencrypt.org/" + DIRECTORY;
    private String name;
    private String url;
    private String stagingUrl;

    public CertificateAuthority(String name, String url, String stagingUrl) {
        this.name = name;
        this.url = url;
        this.stagingUrl = stagingUrl;
    }

    public static CertificateAuthority getDefault() {
        return new CertificateAuthority("LetsEncrypt", LETS_ENCRYPT_URL, LETS_ENCRYPT_STAGING_URL);
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getStagingUrl() {
        return stagingUrl;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setStagingUrl(String stagingUrl) {
        this.stagingUrl = stagingUrl;
    }
}
