package io.jans.configapi.rest.model;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;

public class ClientCertificate implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @NotBlank
    private String format;
    
    @NotBlank
    private String certificate;
    
    
    public String getFormat() {
        return format;
    }
    public void setFormat(String format) {
        this.format = format;
    }
    public String getCertificate() {
        return certificate;
    }
    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
    
    
    @Override
    public String toString() {
        return "ClientCertificate "
                + "["
                +" format=" + format 
                + ", certificate=" + certificate
                + "]";
    }
    
    
    
    

}
