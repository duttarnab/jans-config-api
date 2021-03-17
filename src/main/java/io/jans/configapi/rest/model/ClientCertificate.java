package io.jans.configapi.rest.model;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;

public class ClientCertificate implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotBlank
    private String format;

    @NotBlank
    private String alias;

    @NotBlank
    private String cert;

    @NotBlank
    private String privateKey;

    @NotBlank
    private String publicKey;

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        return "ClientCertificate " + "[" + " format=" + format + ", alias=" + alias + ", cert=" + cert
                + ", privateKey=" + privateKey + ", publicKey=" + publicKey + "]";
    }

}
